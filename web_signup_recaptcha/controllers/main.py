import requests
import werkzeug
from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.addons.web.controllers.main import ensure_db

from odoo import http, _
from odoo.http import request

SIGNUP_PARAM = 'signup_google_recaptcha'
SITE_KEY_PARAM = 'google_recaptcha_site_key'
SECRET_KEY_PARAM = 'google_recaptcha_secret_key'


def verify_recaptcha(captcha_data):
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', captcha_data)
    return r.json()


class AuthSignupHomeRecaptcha(AuthSignupHome):
    def init_recaptcha(self):
        ensure_db()
        params = request.env['ir.config_parameter'].sudo()
        signup_recaptcha = params.get_param(SIGNUP_PARAM)
        recaptcha_site_key = params.get_param(SITE_KEY_PARAM)
        request.params.update({
            'signup_recaptcha': signup_recaptcha,
            'recaptcha_site_key': recaptcha_site_key
        })
        return signup_recaptcha, recaptcha_site_key

    @http.route()
    def web_auth_signup(self, *args, **kw):
        signup_recaptcha, recaptcha_site_key = self.init_recaptcha()
        if request.httprequest.method == 'POST' and signup_recaptcha:
            params = request.env['ir.config_parameter'].sudo()
            qcontext = self.get_auth_signup_qcontext()
            if not qcontext.get('token') and not qcontext.get('signup_enabled'):
                raise werkzeug.exceptions.NotFound()

            is_captcha_verified = False
            if recaptcha_site_key:
                values = request.params.copy()
                captcha_data = {
                    'secret': params.get_param(SECRET_KEY_PARAM),
                    'response': request.params['field-recaptcha-response'],
                }

                response = verify_recaptcha(captcha_data)
                is_captcha_verified = response.get('success')

            print('---- check captcha ----', is_captcha_verified, recaptcha_site_key, captcha_data)

            if not is_captcha_verified:
                values['error'] = _("Invalid reCaptcha")
                response = request.render('auth_signup.signup', values)
                response.headers['X-Frame-Options'] = 'DENY'
                return response

        return super().web_auth_signup(*args, **kw)

    @http.route()
    def web_auth_reset_password(self, *args, **kw):
        signup_recaptcha, recaptcha_site_key = self.init_recaptcha()
        if request.httprequest.method == 'POST' and signup_recaptcha:
            params = request.env['ir.config_parameter'].sudo()
            qcontext = self.get_auth_signup_qcontext()
            if not qcontext.get('token') and not qcontext.get('signup_enabled'):
                raise werkzeug.exceptions.NotFound()

            is_captcha_verified = False
            if recaptcha_site_key:
                values = request.params.copy()
                captcha_data = {
                    'secret': params.get_param(SECRET_KEY_PARAM),
                    'response': request.params['field-recaptcha-response'],
                }

                response = verify_recaptcha(captcha_data)
                is_captcha_verified = response.get('success')

            if not is_captcha_verified:
                values['error'] = _("Invalid reCaptcha")
                response = request.render('auth_signup.reset_password', values)
                response.headers['X-Frame-Options'] = 'DENY'
                return response
        return super().web_auth_reset_password(*args, **kw)
