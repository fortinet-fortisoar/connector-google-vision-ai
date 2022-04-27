# connector-google-vision-ai

Google Vision AI allows you to integrate Google Vision features, including image labeling, face, logo, and landmark detection, optical character recognition (OCR), and detection of explicit content into applications.

## API Documentation Link: https://cloud.google.com/vision/docs/reference/rest

## Google Vision AI Version: v1

# Accessing the Cloud Vision AI API

Google Vision AI in Google Cloud Platform uses OAuth 2.0 for API authentication and authorization. Authentication is the process of determining your identity. The OAuth Client ID and Client Secret are used to identify your app to Google’s OAuth servers. Authorization is the process of determining what permissions your app has against a set of resources.

You can follow the steps below to secure the authentication and authorization codes in order to access the Cloud Vision API:

1.	Ensure that you have created a PROJECT in Google Cloud Platform in the Web Application section so that you can get your CLIENT_ID, CLIENT_SECRET, and REDIRECT_URI, i.e., you must register your application with Google Vision AI. For more information see, https://developers.google.com/adwords/api/docs/guides/authentication#webapp.
2.	In the PROJECT, enable Cloud Vision AI API in APIs and Services. For more information see, https://support.google.com/googleapi/answer/6158841?hl=en&ref_topic=7013279.
Make a note of these authentication codes. In the Configurations tab of the connector, enter the authentication details in the following fields to authenticate the Google Vision AI connector with the Google Vision AI API. 
-	In the Client ID field, enter the client ID
-	In the Client Secret field, enter the client secret
-	In the Redirect URL field, enter the redirect URI. By default, the redirect URI is set to https://localhost/myapp
Now that you have the authentication codes, you can use them to generate the authorization code.
3.	Copy the following URL into a browser and replace the CLIENT_ID and REDIRECT_URI with the client ID and redirect URI generated at the time of registering the application:
https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/cloud-platform
https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/cloud-platform&access_type=offline&include_granted_scopes=true&response_type=code&state=state_parameter_passthrough_value&redirect_uri=REDIRECT_URI&client_id=CLIENT_ID
4.	Enter the link and you will be automatically redirected to a link with the following structure: REDIRECT_URI?state=STATE&code=AUTH_CODE&scope=SCOPE. Copy the AUTH_CODE (without the "code=" prefix) and paste it into the Authorization Code configuration parameter field in the Configurations tab of the connector.


The process to access the Cloud Vision API is now complete.
