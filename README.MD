# Custom Basic Authenticator

------

 This component has been tested with WSO2 IS 5.7.0.

### Steps to deploy
- Build the component by running "mvn clean install"
- Copy  jar file which can be found in target directory into <IS_HOME>/repository/components/dropins/
    
- If you are going to use email address as the `AuthenticatingUsernameClaimUri`
  * Please uncomment following line from <IS_HOME>/repository/conf/carbon.xml
    ```
    <EnableEmailUserName>true</EnableEmailUserName>
    ```
- If you want to use this authenticator for all the service providers
  * update the following properties in the <IS_HOME>/repository/conf/identity/service-providers/default.xml file.
    ```
    <LocalAuthenticatorConfig>
        <Name>CustomBasicAuthenticator</Name>
        <DisplayName>custom-basic</DisplayName>
    ```
  * Also  update the following variable in <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/login.jsp
    ```
    private static final String BASIC_AUTHENTICATOR = "CustomBasicAuthenticator";
    ```
- To use this only for one/few service providers
  * Restart the Identity Server
  * Configure "custom-basic" in authentication steps in Local and Outbound authentication config of the
 service providers instead of "basic".
  * Open <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/login.jsp
  * Add a new variable `CUSTOM_BASIC_AUTHENTICATOR` near the `BASIC_AUTHENTICATOR` as below.
    ```
    private static final String BASIC_AUTHENTICATOR = "BasicAuthenticator";
    private static final String CUSTOM_BASIC_AUTHENTICATOR = "CustomBasicAuthenticator";
    ```
  * Update all the place which has `localAuthenticatorNames.contains(BASIC_AUTHENTICATOR)` as following.
    ```
    localAuthenticatorNames.contains(BASIC_AUTHENTICATOR) || localAuthenticatorNames.contains(CUSTOM_BASIC_AUTHENTICATOR)
    ```
- To use this authenticator for WSO2 IS user dashboard, update the following properties in 
<IS_HOME>/repository/conf/identity/service-providers/sp_dashboard.xml and restart the Identity Server.
    ```
    <LocalAuthenticatorConfig>
        <Name>CustomBasicAuthenticator</Name>
        <DisplayName>custom-basic</DisplayName>
    ```
