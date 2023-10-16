curl --location --request POST 'localhost:3030/v0.0.1/requests' \
-H "Authorization: Bearer PASSWORD" \
--header 'Content-Type: application/json' \
--header 'Content-Type: text/plain' \
--data-raw '{
        "id": "apple",
        "request_type": "generateSwapInitiation"
}'
