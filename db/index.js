const Pool = require("pg").Pool;

const pool = new Pool ({
    user: "postgres",
    password: "abcde567",
    host: "localhost",
    port: 5432,
    database: "unnotate"
});

module.exports = pool;