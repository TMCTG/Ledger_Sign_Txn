# Ledger_Sign
Ledger_Sign.py

This Python script builds a very basic EVM (Ethereum, BSC, etc) transaction, and sends it to a Ledger hardware wallet to be approved.  
*The final step of broadcasting the signed transaction to the network is commented out for safety.*

If you feel comfortable with the code, you can uncomment the line containing sendRawTransaction, and the transaction will be immediately sent after you've signed it on your Ledger.

To see the signed contents of the "Encoded signed transaction", you can paste it here and press **[Decode]**:  
https://flightwallet.github.io/decode-eth-tx/  
*NOTE: If you press **[Publish]** on that site, the transaction WILL be broadcast, and you'll pay gas fees.*

If you're getting errors in Python, make sure the Ledger is unlocked with your PIN and in the correct app (Ethereum)

This code can:  
  * Ask the ledger for wallet addresses.
  * Ask the ledger to prompt you for approval to sign a transaction.  

It CAN NOT:
  * Access your private keys or mnemonic/seed phrase (It's not technically possible.)
