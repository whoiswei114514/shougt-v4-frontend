"""Isolated browser fixture: real cryptography, no PC/SC or production card access."""
import base64
import json
import os
import sys
import threading
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'shougt-sa'))
from backend.piv_bridge import Bridge, BridgeServer
from backend.piv_cli import make_csr, make_certificate, pem
from backend.piv_crypto import write_proof
from backend.piv_policy import SlotConflict

if os.environ.get('SHOUGT_UI_TEST')!='1':
    raise SystemExit('This test fixture requires SHOUGT_UI_TEST=1')
work=Path(os.environ['SHOUGT_UI_WORK'])
fixture=json.loads((work/'fixture.json').read_text('utf-8'))
ca=x509.load_pem_x509_certificate((work/'pki/sub.pem').read_bytes())
root=x509.load_pem_x509_certificate((work/'pki/root.pem').read_bytes())
ca_key=serialization.load_pem_private_key((work/'pki/bridge-test-ca-key.pem').read_bytes(),None)
rsa_ca=x509.load_pem_x509_certificate((work/'pki/rsa-sub.pem').read_bytes())
rsa_ca_key=serialization.load_pem_private_key((work/'pki/bridge-test-rsa-ca-key.pem').read_bytes(),None)
keys={}

def sign(key,message):
    return key.sign(message,padding.PKCS1v15(),hashes.SHA384()) if isinstance(key,rsa.RSAPrivateKey) else key.sign(message,ec.ECDSA(hashes.SHA384()))

def execute(stage,job,options):
    if stage=='generate':
        if options['slot']=='9a':raise SlotConflict(0x9a,0x9c)
        name='RSA-2048' if options['reader']=='mobile:nfc' else ('P-384' if options['algorithm']=='auto' else options['algorithm'])
        key=rsa.generate_private_key(public_exponent=65537,key_size=int(name.split('-')[1])) if name.startswith('RSA-') else ec.generate_private_key(ec.SECP384R1())
        keys[job['issuance_id']]=key
        return {'issuance_id':job['issuance_id'],'csr_pem':pem(make_csr({**job,'card':{'slot':options['slot']}},key.public_key(),lambda message:sign(key,message))),
                'card':{'slot':options['slot'],'algorithm':name,'transport':options['transport'],
                        'protocol':'ISO-DEP' if options['reader']=='mobile:nfc' else 'T=1','on_card_generation':True}}
    if stage=='sign':
        selected,selected_key=(rsa_ca,rsa_ca_key) if job['card']['algorithm'].startswith('RSA-') else (ca,ca_key)
        leaf=make_certificate(job,selected,[selected,root],lambda message:sign(selected_key,message))
        return {**job,'chain_pem':[pem(c) for c in [leaf,selected,root]],'issuer_slot':'9c' if selected is rsa_ca else '9a'}
    leaf=x509.load_pem_x509_certificate(job['chain_pem'][0].encode())
    chain=[x509.load_pem_x509_certificate(value.encode()) for value in job['chain_pem'][1:]]
    return {'issuance_id':job['issuance_id'],'chain_pem':job['chain_pem'],
            'proof':base64.b64encode(sign(keys[job['issuance_id']],write_proof(job,leaf,chain))).decode(),
            'readback_verified':True,'onsite_confirmed':True,'card_slot':job['card']['slot'],'chain_slots':[job['card']['slot'],'82','83']}

cards=[{'id':'fixture-usb','name':'PIVApplet + FIDO2Applet (fixture)','transport':'usb','state':'ready','piv':True,'fido2':True,'default_slot_occupied':True},
       {'id':'fixture-contact','name':'Contact CA (fixture)','transport':'contact','state':'ready','piv':True,'fido2':False},
       {'id':'mobile:nfc','name':'Phone NFC (fixture)','transport':'nfc','platform':'android','state':'ready','piv':True,'fido2':True}]
bridge=Bridge('https://privileged.localhost:18443',executor=execute,inventory=lambda:cards)
bridge.pair_code=fixture['piv_pair_code']
phone_bridge=Bridge('https://privileged.localhost:18443',executor=execute,inventory=lambda:cards)
phone_bridge.pair_code=fixture['piv_phone_pair_code']
phone_server=BridgeServer(18448,phone_bridge)
threading.Thread(target=phone_server.serve_forever,daemon=True).start()
with BridgeServer(18444,bridge) as server:
    try:server.serve_forever()
    finally:phone_server.shutdown();phone_server.server_close()
