package ioc

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/Havens-blog/e-iam/internal/repository/dao"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/Havens-blog/e-iam/pkg/gormx"
	"github.com/ecodeclub/ekit/retry"
)

func InitDB() *gorm.DB {
	db := InitDBWithoutMigrate()

	// AutoMigrate 创建/更新表结构
	if err := dao.InitTables(db); err != nil {
		panic(err)
	}

	// RunMigrations 执行迁移升级 (含 Seed)
	if err := RunMigrations(db); err != nil {
		panic(err)
	}

	return db
}

// InitDBWithoutMigrate 初始化数据库连接并配置基础插件，但不执行 DDL/DML 迁移
func InitDBWithoutMigrate() *gorm.DB {
	dsn := viper.GetString("mysql.dsn")
	WaitForDBSetup(dsn)

	myLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             2 * time.Second,
			LogLevel:                  logger.Error,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
		Logger: myLogger,
	})
	if err != nil {
		panic(err)
	}

	// 显式连接池参数：database/sql 默认 MaxOpenConns=0（无上限），
	// 高峰 + 慢查询时可能打穿 MySQL max_connections(默认 151)，必须收口
	sqlPool, err := db.DB()
	if err != nil {
		panic(err)
	}
	sqlPool.SetMaxOpenConns(100)
	sqlPool.SetMaxIdleConns(30)
	sqlPool.SetConnMaxLifetime(30 * time.Minute)
	sqlPool.SetConnMaxIdleTime(10 * time.Minute)

	// 注册多租户隔离插件
	if err = db.Use(gormx.NewTenantPlugin()); err != nil {
		panic(err)
	}

	return db
}

func WaitForDBSetup(dsn string) {
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}
	// 探测连接仅供启动等待使用，成功后退还底层连接池资源
	defer func() { _ = sqlDB.Close() }()
	const maxInterval = 10 * time.Second
	const maxRetries = 10
	strategy, err := retry.NewExponentialBackoffRetryStrategy(time.Second, maxInterval, maxRetries)
	if err != nil {
		panic(err)
	}

	const timeout = 5 * time.Second
	for {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err = sqlDB.PingContext(ctx)
		cancel()
		if err == nil {
			break
		}
		next, ok := strategy.Next()
		if !ok {
			panic("WaitForDBSetup 重试失败......")
		}
		time.Sleep(next)
	}
}
