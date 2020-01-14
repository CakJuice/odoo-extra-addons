import requests
from odoo.addons.web.controllers.main import Home, ensure_db

from odoo import http, _
from odoo.http import request

params = request.env['ir.config_parameter'].sudo()


def check_login_recaptcha():
    return params.get_param('login_google_recaptcha')


def get_recaptcha_site_key():
    return params.get_param('google_recaptcha_site_key')


def get_recaptcha_secret_key():
    return params.get_param('google_recaptcha_secret_key')


def verify_recaptcha(captcha_data):
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', captcha_data)
    return r.json()


class HomeRecaptcha(Home):
    @http.route()
    def web_login(self, redirect=None, **kw):
        ensure_db()
        login_recaptcha = check_login_recaptcha()
        recaptcha_site_key = get_recaptcha_site_key()
        request.params.update({
            'login_recaptcha': login_recaptcha,
            'recaptcha_site_key': recaptcha_site_key
        })

        if request.httprequest.method == 'POST' and login_recaptcha:
            is_captcha_verified = False
            if recaptcha_site_key:
                values = request.params.copy()
                captcha_data = {
                    'secret': get_recaptcha_secret_key(),
                    'response': request.params['field-recaptcha-response'],
                }

                response = verify_recaptcha(captcha_data)
                is_captcha_verified = response.get('success')

            if not is_captcha_verified:
                values['error'] = _("Invalid reCaptcha")
                response = request.render('web.login', values)
                response.headers['X-Frame-Options'] = 'DENY'
                return response

        return super(HomeRecaptcha, self).web_login(redirect=redirect, **kw)
