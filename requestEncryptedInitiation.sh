curl --location --request POST 'localhost:3030/v0.0.1/requests' \
CoinA-H "Authorization: Bearer PASSWORD" \
--header 'Content-Type: application/json' \
--header 'Content-Type: text/plain' \
--data-raw '{
        "id": "213yu82n3df98",
	"request_type": "publishNewOrderType",
	"OrderTypeUUID": "213yu82n3df98",
	"CoinA": "Ergo",
	"CoinB": "Sepolia",
	"CoinA_price": "0.90",
	"CoinB_price": "1544",
	"MaxVolCoinA": "50"
}'
