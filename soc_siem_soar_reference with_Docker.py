# SOC SIEM + SOAR reference implementation
# File: soc_siem_soar_reference.py
# This single-file reference contains multiple modules separated by big comment headers.
# It implements:
#  - feature extractor for flow-based data (CSV/NetFlow-like)
#  - ML training pipeline (PCA for feature reduction + RandomForest)
#  - real-time consumer that simulates SIEM ingestion (Kafka consumer) and detection
#  - SOAR playbook consumer that triggers SDN mitigation (Ryu/OpenFlow) via REST
#  - simple Ryu-compatible REST call example for flow blocking
#
# NOTE: This file is a reference scaffold. Adjust fields, endpoints, and credentials
# to your environment. Test in a lab before production.

###########################################################################
# Requirements (install via pip):
# pandas scikit-learn joblib kafka-python elasticsearch requests ryu
# Example: pip install pandas scikit-learn joblib kafka-python elasticsearch requests
###########################################################################

###########################################################################
# CONFIGURATION (edit per your environment)
###########################################################################

KAFKA_BOOTSTRAP = 'localhost:9092'
KAFKA_FLOW_TOPIC = 'flows'
KAFKA_ALERT_TOPIC = 'alerts'
ELASTICSEARCH_HOST = 'http://localhost:9200'
ELASTIC_INDEX = 'siem-alerts'
MODEL_FILEPATH = './models/ransomware_rf.joblib'
SDN_CONTROLLER_REST = 'http://localhost:8080'  # Ryu REST API or custom SDN controller
FLOW_BLOCK_ENDPOINT = SDN_CONTROLLER_REST + '/block'  # REST path used in this example

###########################################################################
# 1) Feature extractor (for flow CSVs / NetFlow exports)
###########################################################################

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, f1_score, accuracy_score
import joblib
import json
import time
import threading


def extract_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Accepts a DataFrame with at least the following columns:
    ['ts_start','ts_end','src_ip','dst_ip','src_port','dst_port','protocol','packets','bytes']

    Returns per-flow engineered features suitable for ML.
    """
    df = df.copy()
    # Ensure columns
    df['duration'] = (pd.to_datetime(df['ts_end']) - pd.to_datetime(df['ts_start'])).dt.total_seconds().clip(lower=0.000001)
    df['bytes_per_packet'] = df['bytes'] / df['packets'].replace(0,1)
    df['pkt_rate'] = df['packets'] / df['duration']
    df['byte_rate'] = df['bytes'] / df['duration']
    # Common ports as categorical heuristic
    df['dst_port_is_high'] = (df['dst_port'] > 1024).astype(int)
    # protocol to numeric
    df['protocol_num'] = df['protocol'].map({'TCP':6,'UDP':17}).fillna(0).astype(int)
    # ratio features
    df['bytes_per_second'] = df['bytes'] / df['duration']
    df['packets_per_second'] = df['packets'] / df['duration']
    # Encode IPs via hash (not perfect, but avoids one-hot explosion)
    df['src_ip_hash'] = df['src_ip'].apply(lambda x: hash(x) % (2**16))
    df['dst_ip_hash'] = df['dst_ip'].apply(lambda x: hash(x) % (2**16))

    features = ['duration','bytes_per_packet','pkt_rate','byte_rate','dst_port_is_high',
                'protocol_num','bytes_per_second','packets_per_second','src_ip_hash','dst_ip_hash']
    return df[features]

###########################################################################
# 2) ML training pipeline (PCA + RandomForest) - offline
###########################################################################

def train_model(flow_csv_path: str, label_col: str = 'label'):
    """Train and persist a model. CSV should contain flow features + label column.
    label should be 1 for ransomware/malicious, 0 for benign.
    """
    df = pd.read_csv(flow_csv_path)
    # Extract features
    X = extract_flow_features(df)
    y = df[label_col].astype(int)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # PCA for feature reduction
    pca = PCA(n_components=min(8, X_train_s.shape[1]), random_state=42)
    X_train_p = pca.fit_transform(X_train_s)
    X_test_p = pca.transform(X_test_s)

    # Random Forest
    rf = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
    rf.fit(X_train_p, y_train)

    # Evaluate
    preds = rf.predict(X_test_p)
    print('Accuracy:', accuracy_score(y_test, preds))
    print('F1:', f1_score(y_test, preds))
    print(classification_report(y_test, preds))

    # Cross-validated score on full training
    cv = cross_val_score(rf, np.vstack([X_train_p, X_test_p]), np.hstack([y_train, y_test]), cv=5, scoring='f1')
    print('CV F1 scores:', cv, 'mean:', cv.mean())

    # Persist pipeline components
    joblib.dump({'scaler': scaler, 'pca': pca, 'model': rf}, MODEL_FILEPATH)
    print('Model saved to', MODEL_FILEPATH)

###########################################################################
# 3) Real-time detector (SIEM ingestion simulation)
###########################################################################

from kafka import KafkaConsumer, KafkaProducer
from elasticsearch import Elasticsearch


class RealtimeDetector:
    def __init__(self, kafka_bootstrap=KAFKA_BOOTSTRAP, flow_topic=KAFKA_FLOW_TOPIC, alert_topic=KAFKA_ALERT_TOPIC,
                 es_host=ELASTICSEARCH_HOST, model_path=MODEL_FILEPATH):
        self.consumer = KafkaConsumer(flow_topic, bootstrap_servers=[kafka_bootstrap], value_deserializer=lambda m: json.loads(m.decode('utf-8')))
        self.producer = KafkaProducer(bootstrap_servers=[kafka_bootstrap], value_serializer=lambda m: json.dumps(m).encode('utf-8'))
        self.es = Elasticsearch([es_host])
        self.pipeline = joblib.load(model_path)
        self.scaler = self.pipeline['scaler']
        self.pca = self.pipeline['pca']
        self.model = self.pipeline['model']

    def run(self):
        print('Realtime detector started, listening for flows...')
        for msg in self.consumer:
            flow = msg.value  # expects a dict for a single flow
            try:
                df = pd.DataFrame([flow])
                X = extract_flow_features(df)
                Xs = self.scaler.transform(X)
                Xp = self.pca.transform(Xs)
                pred = int(self.model.predict(Xp)[0])
                score = float(self.model.predict_proba(Xp)[0][1]) if hasattr(self.model,'predict_proba') else None

                alert = {
                    'ts': time.time(),
                    'src_ip': flow.get('src_ip'),
                    'dst_ip': flow.get('dst_ip'),
                    'src_port': flow.get('src_port'),
                    'dst_port': flow.get('dst_port'),
                    'protocol': flow.get('protocol'),
                    'prediction': int(pred),
                    'score': score,
                    'flow': flow
                }

                if pred == 1:
                    # send to ES
                    self.es.index(index=ELASTIC_INDEX, document=alert)
                    # produce to alerts topic for SOAR
                    self.producer.send(KAFKA_ALERT_TOPIC, alert)
                    self.producer.flush()
                    print('Alert produced for', alert['src_ip'])
                else:
                    # Optionally store benign flows or summary metrics
                    pass
            except Exception as e:
                print('Error processing flow:', e)

###########################################################################
# 4) SOAR playbook consumer -> perform mitigation via SDN controller
###########################################################################

import requests

class SOARPlaybook:
    def __init__(self, kafka_bootstrap=KAFKA_BOOTSTRAP, alert_topic=KAFKA_ALERT_TOPIC, es_host=ELASTICSEARCH_HOST):
        self.consumer = KafkaConsumer(alert_topic, bootstrap_servers=[kafka_bootstrap], value_deserializer=lambda m: json.loads(m.decode('utf-8')))
        self.es = Elasticsearch([es_host])

    def block_ip_via_sdn(self, src_ip, duration=3600, reason='ransomware-detected'):
        # POST to SDN controller which will install flows to drop traffic from src_ip
        payload = {'src_ip': src_ip, 'duration': duration, 'reason': reason}
        try:
            resp = requests.post(FLOW_BLOCK_ENDPOINT, json=payload, timeout=5)
            if resp.status_code == 200:
                return True, resp.json()
            else:
                return False, {'status_code': resp.status_code, 'text': resp.text}
        except Exception as e:
            return False, {'error': str(e)}

    def run(self):
        print('SOAR Playbook running, waiting for alerts...')
        for msg in self.consumer:
            alert = msg.value
            src_ip = alert.get('src_ip')
            dst_ip = alert.get('dst_ip')
            ts = alert.get('ts')
            # Enrichment: reverse DNS, geoip, previous alerts (skipped - add as needed)

            # Simple decision logic: block if score high enough or repeated alert
            score = alert.get('score') or 1.0
            should_block = score >= 0.6 or True  # conservative default - customize

            if should_block:
                success, details = self.block_ip_via_sdn(src_ip)
                outcome = {
                    'alert': alert,
                    'action': 'block_ip',
                    'src_ip': src_ip,
                    'success': success,
                    'details': details,
                    'ts_action': time.time()
                }
                # Log action in ES
                self.es.index(index=ELASTIC_INDEX + '-actions', document=outcome)
                print('Action logged for', src_ip, 'success=', success)

###########################################################################
# 5) Example SDN controller small Flask-like REST server that issues OpenFlow rules
#    In real deployments, you'd use Ryu app receiving REST calls and calling
#    ofctl APIs or use ONOS/ODL REST APIs. Below is a simple illustrative handler.
###########################################################################

# This is not a full Ryu app; it's a minimal Flask server that demonstrates how
# a SOAR playbook could call a controller endpoint. You can replace this with
# a Ryu REST API implementation which programs switches with drop rules.

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/block', methods=['POST'])
def block():
    data = request.get_json()
    src_ip = data.get('src_ip')
    duration = data.get('duration', 3600)
    reason = data.get('reason')
    # In a Ryu/OpenFlow environment you would call the controller/inject flow_mod.
    # Here we only simulate and return success. Replace this with actual implementation.
    print(f"[SDN Controller] Block request for {src_ip} for {duration}s reason={reason}")
    # Simulate installing flow
    return jsonify({'status': 'ok', 'src_ip': src_ip, 'duration': duration}), 200

###########################################################################
# 6) Utility: simulate sending flows to Kafka (for testing)
###########################################################################

def simulate_flow_producer(sample_flows, kafka_bootstrap=KAFKA_BOOTSTRAP, topic=KAFKA_FLOW_TOPIC, interval=0.5):
    producer = KafkaProducer(bootstrap_servers=[kafka_bootstrap], value_serializer=lambda m: json.dumps(m).encode('utf-8'))
    for f in sample_flows:
        producer.send(topic, f)
        producer.flush()
        time.sleep(interval)

###########################################################################
# 7) Putting it all together: how to run components (in-proc demo)
###########################################################################

def run_demo_inproc(sample_csv=None):
    # 1) train model if necessary (skip if model exists)
    try:
        pipeline = joblib.load(MODEL_FILEPATH)
        print('Using existing model at', MODEL_FILEPATH)
    except Exception:
        if sample_csv is None:
            raise RuntimeError('No model found and no sample CSV provided for training')
        train_model(sample_csv)

    # 2) start SDN REST server in a thread
    server_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False), daemon=True)
    server_thread.start()

    # 3) start SOAR consumer in a thread (will block listening to kafka)
    soar = SOARPlaybook()
    soar_thread = threading.Thread(target=soar.run, daemon=True)
    soar_thread.start()

    # 4) start realtime detector in a thread
    detector = RealtimeDetector()
    det_thread = threading.Thread(target=detector.run, daemon=True)
    det_thread.start()

    print('Demo components started: SDN REST, RealtimeDetector, SOARPlaybook')
    print('Feed the Kafka topic', KAFKA_FLOW_TOPIC, 'with flow records to see detection and mitigation')

###########################################################################
# 8) README-style usage instructions
###########################################################################

USAGE = '''
Quickstart:
1. Prepare environment: Kafka, Zookeeper, Elasticsearch, and optionally Kibana.
2. Prepare flow CSV with columns: ts_start, ts_end, src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, label
3. Train model: from this file run train_model('flows.csv')
4. Run the SDN REST server: python soc_siem_soar_reference.py --serve-sdn
5. Run RealtimeDetector: python soc_siem_soar_reference.py --run-detector
6. Run SOAR Playbook: python soc_siem_soar_reference.py --run-soar

The file also contains a run_demo_inproc(sample_csv) helper to start everything in-process for a lab/demo.
'''

###########################################################################
# 9) If this file is executed as script, provide CLI for common tasks
###########################################################################

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SOC SIEM+SOAR reference')
    parser.add_argument('--train', help='Train model from CSV path', type=str)
    parser.add_argument('--serve-sdn', help='Run SDN REST server (for demo)', action='store_true')
    parser.add_argument('--run-detector', help='Run realtime detector', action='store_true')
    parser.add_argument('--run-soar', help='Run SOAR playbook', action='store_true')
    parser.add_argument('--demo', help='Run demo in-process with sample CSV', type=str)
    args = parser.parse_args()

    if args.train:
        train_model(args.train)
    if args.serve_sdn:
        app.run(host='0.0.0.0', port=8080)
    if args.run_detector:
        RealtimeDetector().run()
    if args.run_soar:
        SOARPlaybook().run()
    if args.demo:
        run_demo_inproc(args.demo)

###########################################################################
# APPENDIX A: RYU SDN CONTROLLER (Full OpenFlow 1.3 + REST endpoint)
###########################################################################

# File: ryu_sdn_blocker.py
# Place this file on the Ryu controller host and run with: ryu-manager ryu_sdn_blocker.py
# It exposes a REST endpoint /wm/block to block a source IP by installing drop flow(s).

ryu_sdn_blocker = r"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json

# REST path: POST /wm/block

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # store known datapaths
        self.datapaths = {}
        wsgi = kwargs['wsgi'] if 'wsgi' in kwargs else None
        if wsgi:
            mapper = wsgi.mapper
            wsgi.register(BlockController, {'switch_app': self})

    @set_ev_cls(ofp_event.EventOFPStateChange)
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == ev.datapath.STATE_DISPATCHER:
            self.logger.info('Registering datapath: %s', dp.id)
            self.datapaths[dp.id] = dp
        elif ev.state == ev.datapath.STATE_DEAD:
            if dp.id in self.datapaths:
                self.logger.info('Removing datapath: %s', dp.id)
                del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Minimal L2 forwarding to keep switch alive; not central to blocker
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        in_port = msg.match['in_port']
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                                  actions=actions, data=data)
        dp.send_msg(out)

    def install_drop_rule(self, src_ip, priority=50000, idle_timeout=3600):
        # Install drop rule on all datapaths matching IPv4 src_ip -> drop
        for dp in list(self.datapaths.values()):
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
            inst = []  # no actions -> drop
            mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                     instructions=inst, idle_timeout=idle_timeout)
            dp.send_msg(mod)
            self.logger.info('Installed drop for %s on dpid=%s', src_ip, dp.id)


class BlockController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(BlockController, self).__init__(req, link, data, **config)
        self.app = data['switch_app']

    @route('block', '/wm/block', methods=['POST'])
    def block(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
        except ValueError:
            return Response(status=400, body='invalid json')
        src_ip = body.get('src_ip')
        duration = int(body.get('duration', 3600))
        if not src_ip:
            return Response(status=400, body='src_ip required')
        self.app.install_drop_rule(src_ip, idle_timeout=duration)
        return Response(status=200, content_type='application/json', body=json.dumps({'status':'ok','src_ip':src_ip,'duration':duration}))
"""

###########################################################################
# APPENDIX B: docker-compose for Kafka + Zookeeper + Elasticsearch + Kibana
###########################################################################

# File: docker-compose.yml
# Compose v3.8 stack to quickly stand up Kafka + Elasticsearch + Kibana for testing

docker_compose = r"""
version: '3.8'
services:
  zookeeper:
    image: confluentinc/cp-zookeeper:7.4.1
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    ports:
      - '2181:2181'

  kafka:
    image: confluentinc/cp-kafka:7.4.1
    depends_on:
      - zookeeper
    ports:
      - '9092:9092'
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: 'zookeeper:2181'
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092,PLAINTEXT_HOST://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.10
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ports:
      - '9200:9200'

  kibana:
    image: docker.elastic.co/kibana/kibana:7.17.10
    depends_on:
      - elasticsearch
    ports:
      - '5601:5601'
    environment:
      ELASTICSEARCH_HOSTS: 'http://elasticsearch:9200'

volumes:
  esdata:
    driver: local
"""

# Append the Ryu and docker-compose text as files under the canvas for the user to copy.

###########################################################################
# End of updates
###########################################################################

