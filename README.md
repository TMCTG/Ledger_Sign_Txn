# Ledger_Sign_Txn
Ledger_Sign_Txn.py

If you run as is, your ledger will prompt to sign, the signed transaction will be RLP encoded, BUT the transaction won't be processed (that line is commented out for safety)
You can paste the "Encoded signed transaction" in here and press Decode:
https://flightwallet.github.io/decode-eth-tx/

If you press Publish on that site, the transaction WILL be broadcast, and you'll pay gas fees.


If you're getting errors in Python, make sure the Ledger is unlocked with your PIN and in the correct app (Ethereum)

This code can ask the ledger for wallet addresses, and can ask the ledger to ask you for a transaction to be signed.
It CAN NOT access your private keys, mnemonic/seed phrase - It's not technically possible.
