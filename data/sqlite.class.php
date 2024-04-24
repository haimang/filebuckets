<?php

class sqliteDB
{

    private $sqliteResult;
    private $error = '';
    private $createTable =
    <<<TABLE
            /*初始化创建数据表，可创建多个表*/
            CREATE TABLE users
            (hash     CHAR(50)            NOT NULL,
            name     TEXT            NOT NULL,
            email  TEXT            NOT NULL,
            password      TEXT             NOT NULL,
            path   CHAR(50),
            type   CHAR(10),
            status   INTEGER DEFAULT 1,
            delete_perm INTEGER DEFAULT 1,
            add_time DATETIME,
            update_time DATETIME);
            CREATE TABLE files (
                hash CHAR(50)            NOT NULL,
                u_hash CHAR(20)  NOT NULL,
                type CHAR(10) NOT NULL,
                name CHAR(100),
                path CHAR(100),
                size INTEGER,
                ext CHAR(20),
                status   INTEGER DEFAULT 1,
                add_time DATETIME,
                update_time DATETIME,
                FOREIGN KEY (u_hash) REFERENCES users(hash));
TABLE;

    public function __construct($fileName)
    {
        //如果有数据库，则打开数据库
        //如果没有数据库，则创建数据库，并且生成数据表及插入数据
        if (file_exists($fileName)) {
            $this->sqliteResult = new MyDB($fileName);
            if (!$this->sqliteResult) {
                //die("Database error：" . $this->sqliteResult->lastErrorMsg());
            }
        } else {
            $this->sqliteResult = new MyDB($fileName);
            if (!$this->sqliteResult) {
                //die("Database error：" . $this->sqliteResult->lastErrorMsg());
            }

            $this->execute($this->createTable);
        }
    }
    //此方法用于“增、删、改”
    public function execute($sql)
    {
        $this->error = $this->sqliteResult->exec($sql);
    }
    //此方法用于“查”
    public function queryDB($sql)
    {
        $result = $this->sqliteResult->query($sql);
        $i = 0;
        $arr = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $arr[$i] = $row;
            $i += 1;
        }
        return $arr;
    }

    public function __destruct()
    {
        if (!$this->error) {
            //die("Database error：" . $this->sqliteResult->lastErrorMsg());
        }

        $this->sqliteResult->close();
    }
}

class MyDB extends SQLite3
{
    public function __construct($fileName)
    {
        $this->open($fileName);
    }
}
