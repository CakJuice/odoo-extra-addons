import logging

import requests
import werkzeug
from odoo.addons.auth_signup.controllers.main import AuthSignupHome
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.addons.web.controllers.main import ensure_db

from odoo import http, _
from odoo.exceptions import UserError
from odoo.http import request

_logger = logging.getLogger(__name__)

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
        # request.params.update({
        #     'signup_recaptcha': signup_recaptcha,
        #     'recaptcha_site_key': recaptcha_site_key
        # })
        # return signup_recaptcha, recaptcha_site_key
        if signup_recaptcha and recaptcha_site_key:
            return {
                'signup_recaptcha': signup_recaptcha,
                'recaptcha_site_key': recaptcha_site_key
            }
        return {}

    @http.route()
    def web_auth_signup(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()
        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        recaptcha = self.init_recaptcha()
        if recaptcha:
            qcontext.update(recaptcha)

        if request.httprequest.method == 'POST':
            if not recaptcha:
                return super().web_auth_signup()

            params = request.env['ir.config_parameter'].sudo()
            captcha_data = {
                'secret': params.get_param(SECRET_KEY_PARAM),
                'response': qcontext.get('field-recaptcha-response'),
            }

            response = verify_recaptcha(captcha_data)
            is_captcha_verified = response.get('success')

            if not is_captcha_verified:
                qcontext['error'] = _("Invalid reCaptcha")

            if not 'error' in qcontext:
                try:
                    self.do_signup(qcontext)
                    # Send an account creation confirmation email
                    if qcontext.get('token'):
                        user_sudo = request.env['res.users'].sudo().search([('login', '=', qcontext.get('login'))])
                        template = request.env.ref('auth_signup.mail_template_user_signup_account_created',
                                                   raise_if_not_found=False)
                        if user_sudo and template:
                            template.sudo().with_context(
                                lang=user_sudo.lang,
                                auth_login=werkzeug.url_encode({'auth_login': user_sudo.email}),
                            ).send_mail(user_sudo.id, force_send=True)
                    return request.redirect('/web/login')
                except UserError as e:
                    qcontext['error'] = e.name or e.value
                except (SignupError, AssertionError) as e:
                    if request.env["res.users"].sudo().search([("login", "=", qcontext.get("login"))]):
                        qcontext["error"] = _("Another user is already registered using this email address.")
                    else:
                        _logger.error("%s", e)
                        qcontext['error'] = _("Could not create a new account.")

        response = request.render('auth_signup.signup', qcontext)
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    @http.route()
    def web_auth_reset_password(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()
        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        signup_recaptcha, recaptcha_site_key = self.init_recaptcha()
        if request.httprequest.method == 'POST' and signup_recaptcha:
            params = request.env['ir.config_parameter'].sudo()

            is_captcha_verified = False
            if recaptcha_site_key:
                captcha_data = {
                    'secret': params.get_param(SECRET_KEY_PARAM),
                    'response': request.params['field-recaptcha-response'],
                }

                response = verify_recaptcha(captcha_data)
                is_captcha_verified = response.get('success')

            if not is_captcha_verified:
                qcontext['error'] = _("Invalid reCaptcha")
                response = request.render('auth_signup.reset_password', qcontext)
                response.headers['X-Frame-Options'] = 'DENY'
                return response
        return super().web_auth_reset_password(*args, **kw)
