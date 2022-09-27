# A Proxy that forwards messages between the proxy owner and the target number.
# Each message hash is logged on a tamperproof blockchain so the convervation
# can be cryptographically verified for authenticity. Each message is checked
# for PII and redacted according to the redact rules set on the Pangea Console
# (https://console.pangea.cloud)

import os

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

# Load the .env file into environment variables
from dotenv import load_dotenv
load_dotenv()

# Read the target recipients numbers from environment variables
ownerNumber = os.getenv("OWNER_NUMBER")
targetNumber = os.getenv("TARGET_NUMBER")

# Read the Pangea Config Id and Auth Token from the environment variables
pangeaDomain = os.getenv("PANGEA_DOMAIN")
auditToken = os.getenv("PANGEA_AUTH_TOKEN")
auditConfigId = os.getenv("PANGEA_CONFIG_ID")

# Import the Pangea SDK
from pangea.config import PangeaConfig
from pangea.services import Audit
from pangea.services.audit import Event
from pangea.services.audit import AuditException

# Instantiate a Pangea Configuration object with the end point domain and configId
auditConfig = PangeaConfig(domain=pangeaDomain, config_id=auditConfigId)
auditService = Audit(auditToken, config=auditConfig)

# Read the Twilio SID and Auth Token from the environment variables
accountSid = os.getenv("ACCOUNT_SID")
authToken = os.getenv("AUTH_TOKEN")

# Import the Twilio SDK
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse

# Instantiate a Twilio Client using the accountSid and authToken
twilioClient = Client(accountSid, authToken)

@require_POST
@csrf_exempt
def index(request):

    #print(f"Event: {request.POST}")

    # Define a response object, in case a response to the sender is required
    resp = MessagingResponse()

    # Determine the destination number
    if request.POST['From'].endswith(ownerNumber):
      # If the message is from the owner, send it to target
      destinationNumber = targetNumber
    elif request.POST['From'].endswith(targetNumber):
      # If the message is form the target, send it to owner
      destinationNumber = ownerNumber
    else:
      # If the message is from any other number, reply to the sender
      resp.message("AUTOMATED RESPONSE: This is a private communication channel to securely record auditable conversations. Your message will be ignored!")
      return HttpResponse(resp)

    # The number the original message was sent to is the number of the proxy
    proxyNumber = request.POST['To'];

    # The message originally sent to the poxy.
    originalMessage = request.POST['Body']

    # Map the Twilio event details to the Pangea Event object, for example, the
    # source is set to the number that sent the message and the target is the
    # recipient.
    auditData = Event(
        actor=proxyNumber,
        source=request.POST['From'],
        target=destinationNumber,
        message=originalMessage,
        status=request.POST['SmsStatus'],
        action="forwarded",
    )

    try:
        auditResponse = auditService.log(event=auditData, verbose=True)
        print(f"Response: {auditResponse.result.dict(exclude_none=True)}")

        if auditResponse.success:
            print(f"Forwarding message to: {destinationNumber}")

            loggedMessage = auditResponse.result.envelope.event.message

            # Send the logged message to the destinationNumber
            twilioResponse = twilioClient.messages.create(
                body=loggedMessage,
                from_=proxyNumber,
                to=destinationNumber
            )

            if twilioResponse.error_code is None:
                print("SMS successfully sent")

                # If the logged message was modified by the redact rule set,
                # notify the sender via an automated response
                if loggedMessage != originalMessage:
                    print("Redact detected")
                    resp.message("AUTOMATED RESPONSE: You sent a message with sensitive, personal information. Our system redacted that information so that you can remain protected. The recipient of that message cannot access your sensitive information through this conversation.")
            else:
                resp.message(twilioResponse.error_message)
        else:
            print(f"Audit Request Error: {redactResponse.response.text}")
            if redactResponse.result and redactResponse.result.errors:
                for err in redactResponse.result.errors:
                    print(f"\t{err.detail}")
                    resp.message(err.detail)

    except AuditException as e:
        print(f"Log Request Error: {e.message}")
        resp.message(e.message)

    return HttpResponse(resp)
