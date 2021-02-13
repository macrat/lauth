# Development LDAP server settings

**DON'T USE THIS SETTINGS FOR PRODUCTION USE**

## Usage

### 1. Start LDAP server

``` shell
$ cd test-ldap-server
$ docker-compose up -d
```

### 2. Edit database (optional)

- URL: http://localhost:8080
- login DN: `CN=admin,DC=lauth,DC=local`
- password: `asdfg`

### 3. Start Lauth

``` shell
$ lauth -c test-ldap-server/config.toml
```

## Default accounts

**System accounts:**

|ID                        |Password|
|--------------------------|--------|
|CN=admin,DC=lauth,DC=local|asdfg   |
|CN=lauth,DC=lauth,DC=local|zxcvb   |

**User accounts:**

|ID     |Password|
|-------|--------|
|macrat |foobar  |
|j.smith|hello   |
