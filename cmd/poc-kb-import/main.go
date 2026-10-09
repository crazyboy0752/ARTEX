// Command poc-kb-import 把本机 nuclei 模板库索引进 ARTEX 的 POC/EXP 知识库。
//
// 用法：
//
//	go run ./cmd/poc-kb-import [--dir ~/.local/nuclei-templates]
//
// 数据库连接与 server 同口径：环境变量 ARTEX_PG_DSN 优先，否则读配置文件
// 的 database 段。导入按 code='nuclei-<模板id>' 合并刷新，可重复执行。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Autumn-27/artex/config"
	pgdb "github.com/Autumn-27/artex/db"
)

func main() {
	dir := flag.String("dir", "~/.local/nuclei-templates", "本机 nuclei 模板库目录")
	flag.Parse()

	dsn, source, err := config.PostgresDSN()
	if err != nil {
		log.Fatalf("数据库配置缺失: %v", err)
	}
	log.Printf("连接数据库（%s）…", source)
	database, err := pgdb.Open(dsn)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	start := time.Now()
	imported, skipped, err := database.ImportNucleiTemplates(ctx, *dir)
	if err != nil {
		log.Fatalf("导入失败: %v", err)
	}
	fmt.Printf("导入完成：%d 条模板已索引（含更新），%d 个文件跳过，用时 %s\n",
		imported, skipped, time.Since(start).Round(time.Second))

	stats, err := database.PocCategoryStats(ctx)
	if err != nil {
		os.Exit(0)
	}
	fmt.Println("知识库 14 归类分布：")
	for _, c := range pgdb.PocCategories {
		fmt.Printf("  %-15s %-8s %d\n", c.Code, c.Name, stats[c.Code])
	}
}
