import json, subprocess
TOK=open('/home/z/my-project/cookies/policy_token_final.txt').read().strip()
cases=[
 {"action":"*","resource":"proj/default:env/test:flag/zeno-allowed-1"},
 {"action":"updateDescription","resource":"proj/default:env/test:flag/zeno-allowed-1:extra-segment"},
 {"action":"updateDescription","resource":"proj/default:env/test/flag/zeno-allowed-1"},
 {"action":"updateDescription","resource":"PROJ/DEFAULT:ENV/TEST:FLAG/ZENO-ALLOWED-1"},
 {"action":"updateDescription","resource":"proj/default:env/TEST:flag/zeno-allowed-1"},
 {"action":"updateDescription","resource":"proj/default:env/test:flag/zeno-allowed-1;extra"},
 {"action":"updateOn","resource":"proj/default:env/test"},
 {"action":"*","resource":"proj/default:env/test:flag/zeno-allowed-*"},
 {"action":"*","resource":""},
 {"action":"*","resource":"proj/default:env/test:flag/zeno%2Dallowed%2D1"},
 {"action":"*","resource":"account/6ac29057ccacd606b1576cb7:proj/default"},
]
body=json.dumps(cases)
r=subprocess.run(['curl','-s','-m','15','-X','POST','-H',f'Authorization: {TOK}','-H','Content-Type: application/json','-d',body,'-w','\n[%{http_code}]','https://app.launchdarkly.com/internal/authorization/access-check/gonfalon/bulk'],capture_output=True,text=True)
out=r.stdout
code=out.rsplit('[',1)[1] if '[' in out else '?'
body=out.rsplit('\n[',1)[0]
try:
    j=json.loads(body)
    for x in j:
        print(f"{str(x.get('allowed')):5} | {x.get('resource','')[:75]}")
except Exception as e:
    print('raw:', body[:500])
print('[',code)
