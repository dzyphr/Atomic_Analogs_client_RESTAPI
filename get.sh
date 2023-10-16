curl --location --request GET 'localhost:3030/v0.0.1/requests' \
--header 'Content-Type: application/json' \
--header 'Content-Type: text/plain' \
--data-raw '{
	"id": "apple",
	"request_type": "get"
}' \
-H "Authorization: Bearer PASSWORD"

