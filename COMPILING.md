# Compilation Instructions

To manually compile the Lambda, you'll need to contruct the dependencies within a similar environment. I downloaded the AWS Encryption SDK wheel and performed the following:

```
docker run -v $(pwd):/outputs -it lambci/lambda:build-python3.7 bash
cd /outputs
virtualenv env
source env/bin/activate
pip3.7 install --verbose --target env/packaged aws_encryption_sdk-1.4.0-py2.py3-none-any.whl
deactivate
exit
```
