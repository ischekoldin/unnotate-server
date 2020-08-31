const Pool = require("pg").Pool;

const pool = new Pool ({
    user: "ybwlkprwfidvcx",
    password: "7f91bdb938d2c95b9d1c48347ba2a186c959d46db07e91ebfd2be66569215f81",
    host: "ec2-3-217-87-84.compute-1.amazonaws.com",
    port: 5432,
    database: "dbq657v46ql1ge"
});

module.exports = pool;