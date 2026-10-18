"""Real HTTP server/scheduler plus TLS download; generated identities, no live registry."""
import base64,datetime,hashlib,http.client,io,json,os,socket,ssl,subprocess,sys,tarfile,tempfile,threading,time,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec,ed25519
from cryptography.hazmat.primitives import hashes,serialization
from zog.host_identify.archive import issue

def main():
 with tempfile.TemporaryDirectory(prefix='mirror-acceptance-') as temporary:
    root=Path(temporary);host=str(uuid.uuid4());key=ed25519.Ed25519PrivateKey.generate()
    public=root/'public.json';public.write_text(json.dumps({'version':1,'keys':{'test':base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()}}))
    intent=root/'intent.json'
    def write_intent(selected):
        p=root/'intent.new';p.write_text(json.dumps({'version':1,'host_id':host,'desired':{'version':1,'selected':selected,'revision':1,'endpoint':'https://localhost','lease_expires_at':int(time.time())+900}}));p.chmod(0o640);os.replace(p,intent)
    write_intent(True)
    config=root/'config.json';config.write_text(json.dumps({'root':str(root/'store'),'collections':['sources','root-filesystems'],'host_id':host,'intent_file':str(intent),'endpoint':'https://localhost','keyring':str(public),'issuer':'https://test-registry','audience':'test-mirror'}))
    environment={**os.environ,'DJANGO_SETTINGS_MODULE':'zog.archive_mirror.settings','ARCHIVE_MIRROR_STATE':str(root),'ARCHIVE_MIRROR_CONFIGURATION':str(config)}
    def command(*args):return subprocess.run([sys.executable,'-m','zog.archive_mirror',*args],env=environment,check=True,capture_output=True,text=True).stdout
    command('migrate')
    archive=root/'root.tar.xz'
    with tarfile.open(archive,'w:xz') as output:
        member=tarfile.TarInfo('root/etc/fixture');member.size=7;output.addfile(member,io.BytesIO(b'fixture'))
    record=json.loads(command('import',str(archive),'--collection','root-filesystems','--kind','root-filesystem'))
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    processes=[];proxy=None
    try:
        for arguments in (['scheduler'],['serve','--port',str(port)]):
            processes.append(subprocess.Popen([sys.executable,'-m','zog.archive_mirror',*arguments],env=environment,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE))
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            try:
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=1);connection.request('GET','/.well-known/zog/archive-mirror/ready');response=connection.getresponse();data=response.read();connection.close()
                if response.status==200:break
            except OSError:pass
            time.sleep(.2)
        else:raise AssertionError('Runtime never became ready')
        private=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.datetime.now(datetime.timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(private,hashes.SHA256())
        certpath=root/'cert.pem';certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM));keypath=root/'tls.pem';keypath.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5);connection.request('GET',self.path,headers={'Host':'localhost','Authorization':self.headers.get('Authorization','')});upstream=connection.getresponse();body=upstream.read();self.send_response(upstream.status)
                for k,v in upstream.getheaders():
                    if k.lower() not in ('transfer-encoding','connection','server','date'):self.send_header(k,v)
                self.end_headers();self.wfile.write(body);connection.close()
        proxy=ThreadingHTTPServer(('127.0.0.1',0),Proxy);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certpath,keypath);proxy.socket=context.wrap_socket(proxy.socket,server_side=True);threading.Thread(target=proxy.serve_forever,daemon=True).start()
        token=issue(key,'test','https://test-registry','test-mirror',host,['download'],['root-filesystems'])[0]
        def request(path,credential=token):
            c=http.client.HTTPSConnection('localhost',proxy.server_port,context=ssl.create_default_context(cafile=str(certpath)),timeout=5);c.request('GET',path,headers={'Authorization':'Bearer '+credential});r=c.getresponse();data=r.read();status=r.status;c.close();return status,data
        status,data=request('/collections/root-filesystems/archives/'+record['sha256']+'.tar.xz')
        assert status==200 and hashlib.sha256(data).hexdigest()==record['sha256']
        assert request('/collections/sources/')[0]==403
        assert request('/collections/root-filesystems/','bad')[0]==403
        print('PASS: real scheduler/readiness, verified TLS download, checksum, scoped denial, invalid-token denial',flush=True)
        write_intent(False)
        for process in processes:
            try:process.wait(timeout=20)
            except subprocess.TimeoutExpired:raise AssertionError('Process did not stop on role withdrawal')
        assert (root/'store/objects'/record['sha256']).read_bytes()==archive.read_bytes()
        print('PASS: server and scheduler exited after withdrawal; archive retained',flush=True)
    finally:
        if proxy:proxy.shutdown();proxy.server_close()
        for process in processes:
            if process.poll() is None:process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            if process.stderr:process.stderr.close()
if __name__=='__main__':main()
