"""Isolated browser fixture: real cryptography, no PC/SC or production card access."""
import base64
import json
import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'shougt-sa'))
from backend.piv_bridge import Bridge, BridgeServer
from backend.piv_cli import make_csr, make_certificate, pem
from backend.piv_crypto import write_proof

if os.environ.get('SHOUGT_UI_TEST')!='1':
    raise SystemExit('This test fixture requires SHOUGT_UI_TEST=1')
work=Path(os.environ['SHOUGT_UI_WORK'])
fixture=json.loads((work/'fixture.json').read_text('utf-8'))
ca=x509.load_pem_x509_certificate((work/'pki/sub.pem').read_bytes())
root=x509.load_pem_x509_certificate((work/'pki/root.pem').read_bytes())
ca_key=serialization.load_pem_private_key((work/'pki/bridge-test-ca-key.pem').read_bytes(),None)
keys={}

def sign(key,message):
    return key.sign(message,padding.PKCS1v15(),hashes.SHA384()) if isinstance(key,rsa.RSAPrivateKey) else key.sign(message,ec.ECDSA(hashes.SHA384()))

def execute(stage,job,options):
    if stage=='generate':
        key=rsa.generate_private_key(public_exponent=65537,key_size=3072) if options['algorithm']=='RSA-3072' else ec.generate_private_key(ec.SECP384R1())
        keys[job['issuance_id']]=key
        return {'issuance_id':job['issuance_id'],'csr_pem':pem(make_csr(job,key.public_key(),lambda message:sign(key,message))),
                'card':{'slot':'9a','algorithm':options['algorithm'],'transport':options['transport'],'protocol':'T=1','on_card_generation':True}}
    if stage=='sign':
        leaf=make_certificate(job,ca,[ca,root],lambda message:sign(ca_key,message))
        return {**job,'chain_pem':[pem(c) for c in [leaf,ca,root]]}
    leaf=x509.load_pem_x509_certificate(job['chain_pem'][0].encode())
    return {'issuance_id':job['issuance_id'],'chain_pem':job['chain_pem'],
            'proof':base64.b64encode(sign(keys[job['issuance_id']],write_proof(job,leaf,[ca,root]))).decode(),
            'readback_verified':True,'onsite_confirmed':True}

bridge=Bridge('https://privileged.localhost:18443',executor=execute,readers=lambda:['Isolated simulated PIV reader'])
bridge.pair_code=fixture['piv_pair_code']
with BridgeServer(18444,bridge) as server:
    server.serve_forever()
