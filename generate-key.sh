openssl genrsa 4096 >private.key
openssl rsa -pubout <private.key >public.pem
