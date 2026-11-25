import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from aiohttp.test_utils import AioHTTPTestCase
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import app as service

class LicenseTests(AioHTTPTestCase):
    async def get_application(self):
        self.temp=tempfile.TemporaryDirectory()
        return service.create_app(Path(self.temp.name)/'licenses.db','test-admin-secret-not-for-production-92843')
    async def asyncTearDown(self):
        await super().asyncTearDown();self.temp.cleanup()
    async def post(self,path,data,admin=False):
        headers={'X-Admin-Secret':'test-admin-secret-not-for-production-92843'} if admin else {}
        response=await self.client.post(path,json=data,headers=headers)
        return response.status,await response.json()
    async def create(self,name='demo',**extra):
        status,data=await self.post('/admin/users',{'username':name,'password':'demo-password-long','products':['LAWLY'],**extra},True)
        self.assertEqual(status,201,data);return data
    def payload(self,**extra):
        return {'username':'demo','password':'demo-password-long','hwid':'a'*64,'client_id':'b'*64,'product':'LAWLY',**extra}
    async def test_license_lifecycle(self):
        response=await self.client.get('/admin/users');self.assertEqual(response.status,401)
        await self.create(duration_days=30)
        status,data=await self.post('/auth',self.payload(password='wrong'));self.assertEqual(status,403);self.assertEqual(data['code'],'AUTH_INVALID_CREDENTIALS')
        self.assertNotIn('hwid',self.app[service.STORE].get('demo'))
        status,data=await self.post('/auth',self.payload(product='OTHER'));self.assertEqual(data['code'],'AUTH_NO_PERMISSION');self.assertNotIn('hwid',self.app[service.STORE].get('demo'))
        status,data=await self.post('/auth',self.payload());self.assertEqual(status,200,data);token=data['session_token'];self.assertTrue(1<=data['expires_in']<=120)
        status,data=await self.post('/auth',self.payload(password='',session_token=token));self.assertEqual(status,200)
        status,data=await self.post('/auth',self.payload(hwid='c'*64));self.assertEqual(data['code'],'AUTH_HWID_MISMATCH')
        status,data=await self.post('/auth',self.payload(client_id='d'*64));self.assertEqual(data['code'],'AUTH_SESSION_ACTIVE')
        await self.post('/admin/users/pause',{'username':'demo'},True)
        status,data=await self.post('/auth',self.payload(password='',session_token=token));self.assertEqual(status,403)
        status,data=await self.post('/auth',self.payload());self.assertEqual(data['code'],'AUTH_USER_PAUSED')
        await self.post('/admin/users/resume',{'username':'demo'},True)
        status,data=await self.post('/auth',self.payload());self.assertEqual(status,200);token=data['session_token']
        await self.post('/admin/users/password',{'username':'demo','password':'replacement-password'},True)
        status,data=await self.post('/auth',self.payload(session_token=token));self.assertEqual(status,403)
        status,data=await self.post('/auth',self.payload());self.assertEqual(status,403)
        status,data=await self.post('/auth',self.payload(password='replacement-password'));self.assertEqual(status,200)
        await self.post('/admin/users/hwid-reset',{'username':'demo'},True)
        status,data=await self.post('/auth',self.payload(password='replacement-password',hwid='f'*64,client_id='e'*64));self.assertEqual(status,200)
        await self.post('/admin/users/revoke',{'username':'demo'},True)
        status,data=await self.post('/auth',self.payload(password='replacement-password',hwid='f'*64,client_id='e'*64));self.assertEqual(data['code'],'AUTH_USER_REVOKED')
    async def test_admin_cookie_csrf_and_public_data(self):
        status,data=await self.post('/admin/login',{'secret':'bad'});self.assertEqual(status,401)
        status,data=await self.post('/admin/login',{'secret':'test-admin-secret-not-for-production-92843'});self.assertEqual(status,200)
        response=await self.client.get('/admin/users');self.assertEqual(response.status,200)
        response=await self.client.post('/admin/users',json={'username':'demo'});self.assertEqual(response.status,401)
        await self.create()
        response=await self.client.get('/admin/users');data=await response.json();serialized=json.dumps(data);self.assertNotIn('password_hash',serialized);self.assertNotIn('demo-password-long',serialized);self.assertNotIn('salt',serialized)
        response=await self.client.post('/admin/users/delete',json={'username':'demo'},headers={'X-Lawly-Admin':'1','Origin':'https://attacker.example'});self.assertEqual(response.status,403)
        response=await self.client.get('/admin');self.assertEqual(response.status,200);self.assertIn("script-src 'self'",response.headers['Content-Security-Policy'])
    async def test_expiry_persistence_rotation_and_logout(self):
        await self.create(expires_at=service.iso(service.now()-10))
        status,data=await self.post('/auth',self.payload());self.assertEqual(data['code'],'AUTH_USER_EXPIRED')
        await self.post('/admin/users/edit',{'username':'demo','expires_at':''},True)
        status,data=await self.post('/auth',self.payload());self.assertEqual(status,200);first=data['session_token']
        store=self.app[service.STORE];store.db.close();store.db=service.sqlite3.connect(store.path,isolation_level=None)
        status,data=await self.post('/auth',self.payload(password='',session_token=first));self.assertEqual(status,200)
        status,data=await self.post('/auth',self.payload());self.assertEqual(status,200);second=data['session_token'];self.assertNotEqual(first,second)
        status,data=await self.post('/auth',self.payload(password='',session_token=first));self.assertEqual(status,403)
        status,data=await self.post('/auth',self.payload(password='',session_token=second,logout=True));self.assertEqual(status,200)
        status,data=await self.post('/auth',self.payload(client_id='c'*64));self.assertEqual(status,200)
        raw=store.db.execute('SELECT record FROM users').fetchone()[0];self.assertNotIn('demo-password-long',raw);self.assertNotIn(second,raw)
    async def test_invalid_inputs_and_atomic_duplicate(self):
        status,data=await self.post('/admin/users',{'username':{},'password':'x'},True);self.assertEqual(status,400)
        await self.create()
        status,data=await self.post('/admin/users',{'username':'demo','password':'another-password','products':['LAWLY']},True);self.assertEqual(status,409)
        status,data=await self.post('/auth',self.payload(hwid='bad'));self.assertEqual(status,400)
        status,data=await self.post('/admin/users/edit',{'username':'demo','expires_at':'not-date'},True);self.assertEqual(status,400)
        self.assertIsNone(self.app[service.STORE].get('demo')['expires_at'])
        for _ in range(32):
            status,data=await self.post('/auth',self.payload(hwid='bad'))
        self.assertEqual(status,429)

if __name__=='__main__':unittest.main()
