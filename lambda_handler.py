"""AWS Lambda entry point for the CyberUzCheck backend.

Deploy behind API Gateway / a Lambda Function URL. Requires `mangum`:

    pip install mangum

    # zappa users can instead point at ai_extencion.app directly.

Lambda handler string:  lambda_handler.handler
"""

from mangum import Mangum

from ai_extencion import app

handler = Mangum(app, lifespan="off")
