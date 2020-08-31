const Pool = require("pg").Pool;


let pool;

if (!process.env.NODE_ENV || process.env.NODE_ENV === 'development') {
    pool = new Pool ({
        user: "postgres",
        password: "abcde567",
        host: "localhost",
        port: 5432,
        database: "unnotate"
    });
} else {
    pool = new Pool ({
        user: "ybwlkprwfidvcx",
        password: "7f91bdb938d2c95b9d1c48347ba2a186c959d46db07e91ebfd2be66569215f81",
        host: "ec2-3-217-87-84.compute-1.amazonaws.com",
        port: 5432,
        database: "dbq657v46ql1ge"
    });
}


module.exports = pool;