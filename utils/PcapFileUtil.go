package utils

import (
	"time"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"container/list"
	"errors"
)

const PathSeparator = string(os.PathSeparator)

/*
获取特定文件下下边的特定后缀的文件列表。
返回的是文件的绝对路径
 */
func listFolderFilex(path string, suffix string)(*list.List, error){
	dir, err := ioutil.ReadDir(path)

	if err != nil {
		return nil, err
	}

	fileAbsoluteNameList := list.New()

	for _, it := range dir{

		if it.IsDir(){
			continue
		}

		fullPath := path + PathSeparator + it.Name()

		if 0 == len(strings.TrimSpace(suffix)){
			fileAbsoluteNameList.PushBack(fullPath)

		}else if strings.HasSuffix(fullPath, suffix){
			fileAbsoluteNameList.PushBack(fullPath)
		}
	}

	return fileAbsoluteNameList, nil
}

// 将正在处理的文件命名成dealing
func RenamePcapFileToDealing(filePath string) (string, error){

	if ! strings.HasSuffix(filePath, ".pcap"){
		return "", errors.New("error.there is no .pacp suffix in the filepath : "+ filePath)
	}

	timeFlag := time.Now().Format("20060102150405")

	newPath := filePath + "." + timeFlag +".dealing"

	return newPath, os.Rename(filePath, newPath)
}

// 将dealing的后缀文件命名成done后缀
func RenamePcapDealingFileToDone(filePath string) (string, error){

	if ! strings.HasSuffix(filePath, ".dealing"){
		return "", errors.New("error.there is no .dealing suffix in the filepath : "+ filePath)
	}

	newPath := strings.Replace(filePath, ".dealing", ".done", 1)
	return newPath, os.Rename(filePath, newPath)
}

/*
获取特定文件下下边的特定后缀的文件列表。
返回的是文件的绝对路径
 */
func ListFolderFile(path string, suffix string)([]string, error){
	dir, err := ioutil.ReadDir(path)

	if err != nil {
		return nil, err
	}

	var fileAbsoluteNameSlice []string

	for _, it := range dir{

		if it.IsDir(){
			continue
		}

		fullPath := path + PathSeparator + it.Name()

		if 0 == len(strings.TrimSpace(suffix)){
			fileAbsoluteNameSlice = append(fileAbsoluteNameSlice, fullPath)

		}else if strings.HasSuffix(fullPath, suffix){
			fileAbsoluteNameSlice = append(fileAbsoluteNameSlice, fullPath)
		}
	}

	return fileAbsoluteNameSlice, nil
}


// 获取文件夹中文件切片。并且返回其中的number个元素
func FetchNumberFolderFile(path string, suffix string, number int)([]string, error){
	fileSlice,err := ListFolderFile(path, suffix)

	if err!= nil {
		return nil, err
	}

	if number < 0 {
		return nil, errors.New(fmt.Sprintf("元素个数必须大于0，当前传递进来的数字为: %d",number))
	}

	var minNumber int

	length := len(fileSlice)

	if length > number {
		minNumber = number
	}else{
		return fileSlice, nil
	}

	return fileSlice[:minNumber],nil
}


func main() {

	ticker := time.NewTicker(5 * time.Second)

	RenamePcapFileToDealing("C:/Users/igaol/Desktop/tt.pcap")

	RenamePcapDealingFileToDone("C:/Users/igaol/Desktop/tt.pcap.20180815111331.dealing")


	dirpath := "C:/Users/igaol/Desktop"

	ary := [...]string{"A","B","C","D"}

	fmt.Println(ary[:len(ary)])


	for {
		select {
		case <- ticker.C:
		}

		fmt.Println("======================================================")

		fmt.Println(time.Now().Format("2006-01-02 15:04:05"))

		fmt.Println(time.Now().Format("20060102150405"))


		sl, err := FetchNumberFolderFile(dirpath,".pcap", 0)

		if err != nil {
			panic(err)
		}

		for idx, v := range sl{
			fmt.Println(idx, v)
		}

		/*lst, err := ListFolderFile(dirpath,".pcap")

		if err!=nil{
			panic(err)
		}

		for e := lst.Front(); e != nil; e = e.Next() {
			fmt.Print(e.Value, " ")
		}*/
	}
}
