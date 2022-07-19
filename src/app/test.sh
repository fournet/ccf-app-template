
curl -k https://127.0.0.1:8000/app/log?id=43 --data-binary '{"msg": "Junk"}' -H "Content-type: application/json"
curl -k https://127.0.0.1:8000/app/log?id=14 --data-binary '{"msg": "Junk"}' -H "Content-type: application/json"
curl -k https://127.0.0.1:8000/app/log?id=53 --data-binary '{"msg": "Junk"}' -H "Content-type: application/json"
curl -k https://127.0.0.1:8000/app/log?id=54 --data-binary '{"msg": "Junk"}' -H "Content-type: application/json"
curl -k https://127.0.0.1:8000/app/log?id=64 --data-binary '{"msg": "Junk"}' -H "Content-type: application/json"
curl -k https://127.0.0.1:8000/app/refresh
curl -k https://127.0.0.1:8000/app/read_receipt?id=14
curl -k https://127.0.0.1:8000/app/read_receipt?id=43
curl -k https://127.0.0.1:8000/app/log?id=43 --data-binary '{"msg": "Junk"}' -H "Content-type: application/json"
curl -k https://127.0.0.1:8000/app/refresh
curl -k https://127.0.0.1:8000/app/read_receipt?id=14
curl -k https://127.0.0.1:8000/app/read_receipt?id=43
