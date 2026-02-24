$ curl -X POST https://lutetia-api-little-sea-4696.fly.dev/decompile   -H "Content-Type: application/json"   -d '{"bytecode": "602a60005500"}'
{"format":"text","output":"def storage:\n  stor0 is uint256 at storage 0\n\ndef fallback() payable:\n  stor0 = 42\n\n"}Air-de-Jose:lutetia-api joseignacio$ 

add web with address, dropdown chain, hexa bytecode, and decompiled frame with Python highlihgin