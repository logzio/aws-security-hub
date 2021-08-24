# Logzio AWS Security Hub Collector

This integration ships events from AWS Security Hub to Logz.io.

A new event triggers a designated EventBridge rule, which invokes a Lambda function.
The function processes the event and sends it to Logz.io.

## Launch Collector Stack
To launch a new stack that will create the mentioned resources, click the button with your preferred AWS region, and follow the instructions below.

| AWS Region | Launch a stack |
| --- | --- |
| `us-east-1` | [![Deploy to AWS](https://dytvr9ot2sszz.cloudfront.net/logz-docs/lights/LightS-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=logzio-security-hub-collector&templateURL=https://logzio-aws-integrations-us-east-1.s3.amazonaws.com/aws-security-hub-collector/0.0.1/template.yaml) |

After clicking the button, you'll be taken to the AWS Console, where you'll need to follow those steps:

### Step 1 - Specify template

Keep the defaults and press the `Next` button.

TODO - INSERT SCREENSHOT STEP1 HERE

### Step 2 - Specify stack details

Under the `Parameters` section, you'll need to fill the following:

| Parameter | Description |
| --- | --- |
| `logzioListener` | Your Logz.io [listener url](https://docs.logz.io/user-guide/accounts/account-region.html), followed by port `8070` or `8071`. For example - `https://listener.logz.io:8071` |
| `logzioLogLevel` | Log level for the Lambda function. Defaults to `info`. Valid options are: `debug`, `info`, `warn`, `error`, `fatal`, `panic`. |
| `logzioOperationsToken` | Your Logz.io [operations token](https://app.logz.io/#/dashboard/settings/general) |

After filling the parameters, click the `Next` button.

TODO - INSERT SCREENSHOT STEP2 HERE

### Step 3 - Configure stack options

If you want to, fill Tags to easily identify your resources.
Click `Next`.

TODO - INSERT SCREENSHOT STEP3 HERE

### Step 4 - Review

AWS will automatically show a notice requesting that you acknowledge that AWS CloudFormation might create IAM resources. Check the box and click `Create Stack`.

TODO - INSERT SCREENSHOT STEP4A HERE
TODO - INSERT SCREENSHOT STEP4B HERE

### Ship events

Wait a few minutes for the stack to be deployed.
Once deployed, whenever a new AWS Security Hub event will be created, it will be shipped directly to your Logz.io account.

## Resources

This auto-deployment will create the following resources in your AWS account:

TODO - INSERT TEMPLATE SCHEMA HERE

| Resource Name | Resource Type |
| --- | --- |
| `logzioSecurityHubCollector` | `AWS::Lambda::Function` |
| `lambdaPermissions` | `AWS::Lambda::Permission` |
| `eventRule` | `AWS::Events::Rule` |
| `lambdaIamRole` | `AWS::IAM::Role` |