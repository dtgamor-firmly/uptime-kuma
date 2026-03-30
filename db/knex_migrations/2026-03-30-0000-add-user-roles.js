exports.up = function (knex) {
    return knex.schema.alterTable("user", function (table) {
        // role: "admin", "developer", "readonly"
        table.string("role", 20).notNullable().defaultTo("admin");
    });
};

exports.down = function (knex) {
    return knex.schema.alterTable("user", function (table) {
        table.dropColumn("role");
    });
};
