/**
A Proxy that forwards messages between the proxy owner and the target number.
Each message hash is logged on a tamperproof blockchain so the convervation can
be cryptographically verified for authenticity. Each message is checked for PII
and redacted according to the redact rules set on the Pangea Console
(https://console.pangea.cloud)
***/
exports.handler = function(context, event, callback) {

  console.log("Event:", event);

  // Read the target recipients numbers from environment variables
  const ownerNumber = context.OWNER_NUMBER;
  const targetNumber = context.TARGET_NUMBER;

  // Import the Pangea SDK
  const Pangea = require('pangea-node-sdk');

  // Read the Pangea Domain and Auth Token from the environment variables
  const pangeaDomain = context.PANGEA_DOMAIN;
  const auditToken = context.PANGEA_AUTH_TOKEN;

  // Instantiate a Pangea Configuration object with the end point domain
  const auditConfig = new Pangea.PangeaConfig({ domain: pangeaDomain});

  const auditService = new Pangea.AuditService(auditToken, auditConfig);

  // Read the Twilio SID and Auth Token from the environment variables
  const accountSid = context.TWILIO_ACCOUNT_SID;
  const authToken = context.TWILIO_AUTH_TOKEN;

  // Import the Twilio SDK
  const TwilioClient = require('twilio')(accountSid, authToken);

  // Define a response object, in case a response to the sender is required
  const twiml = new Twilio.twiml.MessagingResponse();

  var destinationNumber;

  // Determine the destination number
  if(event.From.endsWith(ownerNumber)) {
    // If the message is from the owner, send it to target
    destinationNumber = targetNumber;
  } else if(event.From.endsWith(targetNumber)) {
    // If the message is form the target, send it to owner
    destinationNumber = ownerNumber;
  } else {
    // If the message is from any other number, reply to the sender
    twiml.message("AUTOMATED RESPONSE: This is a private communication channel to securely record auditable conversations. Your message will be ignored!");
    return callback(null, twiml);
  }

  // The number the original message was sent to is the number of the proxy
  var proxyNumber = event.To;

  // The message originally sent to the poxy
  var originalMessage = event.Body;

  // Map the event details to the auditData object, for example, the source
  // is set to the number that sent the message and the target is the recipient
  const auditData = {
    actor: proxyNumber,
    source: event.From,
    target: destinationNumber,
    message: originalMessage,
    status: event.SmsStatus,
    action: "forwarded"
  };

  const auditOptions = {
    verbose: true,
  };

  // Log the message using the Pangea Audit service. Hashes of each message will
  // be recorded on a tamper proof blockchain so the conversation can be
  // cryptographically proven to be unmodified.
  auditService.log(auditData, auditOptions)
    .then(function(response) {

      console.log("Response: ", response.data);

      if(response.success) {

        console.log("Forwarding message to: ", destinationNumber);

        // Get the logged message returned by the Pangea Secure Audit Log service
        const loggedMessage = response.result.envelope.event.message;

        // Send the logged message to the destination number
        TwilioClient.messages
          .create({body: loggedMessage, from: proxyNumber, to: destinationNumber})
          .then((response) => {

            console.log("SMS successfully sent");
            
            if(originalMessage !== loggedMessage) {
              // If the logged message was modified by the redact rule set,
              // notify the sender via an automated response
              console.log("Redact detected");
              twiml.message("AUTOMATED RESPONSE: You sent a message with sensitive, personal information. Our system redacted that information so that you can remain protected. The recipient of that message cannot access your sensitive information through this conversation.");
            }
            return callback(null, twiml);
          })
          .catch((error) => {
            console.log("Error: ", error);
            return callback(error);
          });

      } else {
        twiml.message("Failed!");
        return callback(null, twiml);
      }

    }).catch(function(error) {
      console.log("Error: ", error);
      twiml.message("Error!");
      return callback(null, twiml);
    });
};
