-- Your SQL goes here

CREATE TABLE "user"
(
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL,
    "hash" TEXT NOT NULL
    "banned" BOOLEAN NOT NULL DEFAULT 0
);