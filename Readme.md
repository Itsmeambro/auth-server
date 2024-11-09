Authorization: Basic Y2xpZW50OnNlY3JldA==

http://localhost:8080/oauth2/token
//redirect_uri:http://127.0.0.1:8080/login/oauth2/code/oidc-client
//response_type:code
//secret:secret
//client_id:client
//client_secret:secret
//scope:openid profile offline_access
grant_type:client_credentials
//username:user
//password:user


*
curl --location 'http://localhost:8080/oauth2/token?scope=openid%2C%20profile&grant_type=upassword&username=user&password=user' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Content-Type: application/json' \
--header 'Cookie: JSESSIONID=865DFDD10EF2942EFB1CBAB2D0F10FE7' \
--data '{
    "username" : "user",
    "password" : "user"
}'

curl --location 'http://localhost:8080/oauth2/token' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Cookie: JSESSIONID=865DFDD10EF2942EFB1CBAB2D0F10FE7' \
--data-urlencode 'grant_type=refresh_token' \
--data-urlencode 'refresh_token=_mqXtFUUIewKQYC7tClVM3l405OybgRHCGFxUxBDdMvdI2WfSKXA22m8XL-OdQ3sNUQNaQ4lEUAZL0t6bM-0cEl5wtpSzb_kF_AuJQrH30h33mGYnKCyuvqaEoxRJf1d'