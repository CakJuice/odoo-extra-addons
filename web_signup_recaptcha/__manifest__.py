# -*- coding: utf-8 -*-
{
    'name': "Web Signup Recaptcha",
    'summary': """
        Signup using Google Recaptcha v3""",
    'description': """
Protect signup & reset password page with Google Recaptcha
============================================
1. Register recaptcha key https://www.google.com/recaptcha/admin/create
2. Go to Settings -> General Settings -> Integrations. Check "Signup Recaptcha" and input your key.
3. Make sure that recaptcha logo appear on signup & reset password page.
    """,
    'author': "Cak Juice",
    'website': "https://cakjuice.com",
    'category': 'Uncategorized',
    'version': '13.0.1',
    'images': [],
    'depends': ['auth_signup'],
    'data': [
        'views/res_config_settings_views.xml',
        'templates/auth_signup_templates.xml',
    ],
    'application': False,
    'installable': True,
    'license': 'LGPL-3',
}
