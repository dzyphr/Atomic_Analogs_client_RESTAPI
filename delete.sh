curl --request DELETE 'localhost:3030/v0.0.1/requests' \
--header 'Content-Type: application/json' \
--header 'Content-Type: text/plain' \
--data-raw '{
        "id": "apple"
}' \
-H "Authorization: Bearer PASSWORD"
