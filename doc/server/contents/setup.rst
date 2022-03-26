Setup
-----

Create an environment::

    virtualenv -ppython3 env
    source env/bin/activate

Install::

    pip install idpyoidc

Get the usage examples::

    git clone https://github.com/identitypython/idpy-oidc.git
    cd idpy-oidc/example/flask_op/
    bash run.sh


You can find an example configuration in `example/flask_op/config.json`.
If you want to do something else the example configuration can be a good
starting point.

This is the expected result from running the script::

    flask_op % bash run.sh
    2022-03-25 08:49:22,801 root DEBUG Configured logging using dictionary
     * Serving Flask app "oidc_op" (lazy loading)
     * Environment: production
       WARNING: This is a development server. Do not use it in a production deployment.
       Use a production WSGI server instead.
     * Debug mode: on
    2022-03-25 08:49:22,841 werkzeug INFO  * Running on https://127.0.0.1:5000/ (Press CTRL+C to quit)
    2022-03-25 08:49:22,842 werkzeug INFO  * Restarting with stat
    2022-03-25 08:49:23,202 root DEBUG Configured logging using dictionary
    2022-03-25 08:49:23,240 werkzeug WARNING  * Debugger is active!
    2022-03-25 08:49:23,245 werkzeug INFO  * Debugger PIN: 162-062-616



If you open your browser at `https://127.0.0.1:5000/.well-known/openid-configuration`
you will get the OpenID Provider Configuration resource.
