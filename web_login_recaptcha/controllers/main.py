import requests
from odoo.addons.web.controllers.main import Home, ensure_db

from odoo import http, _
from odoo.http import request


class HomeRecaptcha(Home):
    @http.route()
    def web_login(self, redirect=None, **kw):
        ensure_db()
        params = request.env['ir.config_parameter'].sudo()
        login_recaptcha = params.get_param('login_google_recaptcha')
        recaptcha_site_key = params.get_param('google_recaptcha_site_key')
        request.params.update({
            'login_recaptcha': login_recaptcha,
            'recaptcha_site_key': recaptcha_site_key
        })

        if request.httprequest.method == 'POST' and login_recaptcha and recaptcha_site_key:
            values = request.params.copy()
            captcha_data = {
                'secret': params.get_param('google_recaptcha_secret_key'),
                'response': request.params['field-recaptcha-response'],
            }
            r = requests.post('https://www.google.com/recaptcha/api/siteverify', captcha_data)
            response = r.json()
            if not response['success']:
                values['error'] = _("Invalid reCaptcha")
                response = request.render('web.login', values)
                response.headers['X-Frame-Options'] = 'DENY'
                return response

        return super(HomeRecaptcha, self).web_login(redirect=redirect, **kw)
