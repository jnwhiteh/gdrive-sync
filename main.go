package main

import (
	"crypto/md5"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"code.google.com/p/goauth2/oauth"
	drive "code.google.com/p/google-api-go-client/drive/v2"
)

var config = &oauth.Config{
	ClientId:     "", // Set by --clientid or --clientid_file
	ClientSecret: "", // Set by --secret or --secret_file
	Scope:        "", // filled in per-API
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
}

// Flags
var (
	clientId     = flag.String("clientid", "", "OAuth Client ID.  If non-empty, overrides --clientid_file")
	clientIdFile = flag.String("clientid_file", "clientid.dat",
		"Name of a file containing just the project's OAuth Client ID from https://code.google.com/apis/console/")
	secret     = flag.String("secret", "", "OAuth Client Secret.  If non-empty, overrides --secret_file")
	secretFile = flag.String("secret_file", "clientsecret.dat",
		"Name of a file containing just the project's OAuth Client Secret from https://code.google.com/apis/console/")
	cacheToken  = flag.Bool("cachetoken", true, "cache the OAuth token")
	debug       = flag.Bool("debug", false, "show HTTP traffic")
	driveFolder = flag.String("drivefolder", "", "The name of a folder on Googel Drive")
	localFolder = flag.String("localfolder", "", "The folder on the local file system")
)

func getDriveFilesByFolder(service *drive.Service, folderName string) (map[string]*drive.File, string) {
	query := fmt.Sprintf("mimeType = 'application/vnd.google-apps.folder' and title = '%s'", folderName)
	folderList, err := service.Files.List().Q(query).Do()
	log.Printf("Got folderList, err: %#v, %v", folderList, err)

	if len(folderList.Items) != 1 {
		log.Fatalf("Number of folders: %d != 1 for %s on Google Drive", len(folderList.Items), *driveFolder)
	}

	files := make(map[string]*drive.File)

	folderId := folderList.Items[0].Id
	query = fmt.Sprintf("'%s' in parents", folderId)
	fileList, err := service.Files.List().Q(query).Do()
	log.Printf("Got fileList, err: %#v, %v", fileList, err)
	for _, file := range fileList.Items {
		key := fmt.Sprintf("%s:%s", file.Title, file.Md5Checksum)
		files[key] = file
	}

	doPaging := true
	for doPaging && fileList.NextPageToken != "" {
		log.Printf("Going to the next page")
		fileList, err = service.Files.List().Q(query).PageToken(fileList.NextPageToken).Do()
		for _, file := range fileList.Items {
			key := fmt.Sprintf("%s:%s", file.Title, file.Md5Checksum)
			files[key] = file
		}
	}

	return files, folderId
}

type File struct {
	filename string
	base     string
	md5      string
}

func getLocalFiles(folderName string) map[string]File {
	files := make(map[string]File)

	glob := filepath.Join(folderName, "*")
	filenames, _ := filepath.Glob(glob)
	for _, filename := range filenames {
		fileInfo, err := os.Stat(filename)
		if err != nil {
			log.Fatalf("Failed to stat %s", filename)
		}
		if fileInfo.IsDir() || strings.HasPrefix(fileInfo.Name(), ".") {
			continue
		}

		file, err := os.Open(filename)
		if err != nil {
			log.Fatalf("Failed to open %s", filename)
		}

		md5er := md5.New()
		io.Copy(md5er, file)
		hash := fmt.Sprintf("%x", md5er.Sum(nil))
		file.Close()

		base := filepath.Base(filename)
		key := fmt.Sprintf("%s:%s", base, hash)
		files[key] = File{filename, base, hash}
	}

	return files
}

func mergeFolders(driveFiles map[string]*drive.File, localFiles map[string]File) []File {
	var remote []*drive.File
	var local []File

	synced := make(map[string]bool)

	for key, file := range driveFiles {
		_, ok := localFiles[key]
		if !ok {
			remote = append(remote, file)
		} else {
			synced[key] = true
		}
	}

	for key, file := range localFiles {
		_, ok := driveFiles[key]
		if !ok {
			local = append(local, file)
		} else {
			synced[key] = true
		}
	}

	fmt.Printf("%v files are synced correctly\n", len(synced))

	if len(remote) > 0 {
		fmt.Printf("%v files are visible on remote but not local\n", len(remote))
		for _, file := range remote {
			fmt.Printf("%v\t%v\t%v\t%v\t%v\n",
				file.Title,
				file.FileSize,
				file.OwnerNames,
				file.Md5Checksum,
				file.Id,
			)
		}
	}

	if len(local) > 0 {
		fmt.Printf("%v files have not been synched\n", len(local))
		for _, file := range local {
			fmt.Printf("%v\t%v\n",
				file.filename,
				file.md5,
			)
		}
	}

	return local
}

func main() {
	flag.Parse()

	config.Scope = drive.DriveScope
	config.ClientId = valueOrFileContents(*clientId, *clientIdFile)
	config.ClientSecret = valueOrFileContents(*secret, *secretFile)

	client := getOAuthClient(config)
	service, _ := drive.New(client)

	// Get the ID here
	driveFiles, folderId := getDriveFilesByFolder(service, *driveFolder)
	localFiles := getLocalFiles(*localFolder)

	toSync := mergeFolders(driveFiles, localFiles)

	// Synchronization
	fmt.Printf("Synchronizing %v files", len(toSync))

	work := make(chan uploadRequest, 1)
	done := make(chan bool, len(toSync))
	for i := 0; i < 3; i++ {
		go uploadWorker(service, work, done)
	}

	total := len(toSync)
	for _, file := range toSync {
		goFile, err := os.Open(file.filename)
		if err != nil {
			log.Fatalf("Could not open file %s: %s", file.filename, err)
		}
		driveFile := drive.File{
			Title: file.base,
			Parents: []*drive.ParentReference{
				&drive.ParentReference{Id: folderId},
			},
		}

		work <- uploadRequest{&driveFile, goFile, file.filename}
		total = total - 1
		log.Printf("%d files left to sync", total)
	}

	for _, _ = range toSync {
		<-done
	}
	log.Printf("Done synchronizing!")
}

type uploadRequest struct {
	driveFile *drive.File
	localFile *os.File
	filename  string
}

func uploadWorker(service *drive.Service, work <-chan uploadRequest, done chan bool) {
	for req := range work {
		log.Printf("++ Uploading %s", req.filename)
		_, err := service.Files.Insert(req.driveFile).Media(req.localFile).Do()
		if err != nil {
			log.Fatalf("Failed when uploading %s: %s", req.filename, err)
		}

		log.Printf("-- Done uploading %s", req.filename)
		req.localFile.Close()
		done <- true
	}
}

func osUserCacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(os.Getenv("HOME"), "Library", "Caches")
	case "linux", "freebsd":
		return filepath.Join(os.Getenv("HOME"), ".cache")
	}
	log.Printf("TODO: osUserCacheDir on GOOS %q", runtime.GOOS)
	return "."
}

func tokenCacheFile(config *oauth.Config) string {
	hash := fnv.New32a()
	hash.Write([]byte(config.ClientId))
	hash.Write([]byte(config.ClientSecret))
	hash.Write([]byte(config.Scope))
	fn := fmt.Sprintf("gdrive-sync-tok%v", hash.Sum32())
	return filepath.Join(osUserCacheDir(), url.QueryEscape(fn))
}

func tokenFromFile(file string) (*oauth.Token, error) {
	if !*cacheToken {
		return nil, errors.New("--cachetoken is false")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	t := new(oauth.Token)
	err = gob.NewDecoder(f).Decode(t)
	return t, err
}

func saveToken(file string, token *oauth.Token) {
	f, err := os.Create(file)
	if err != nil {
		log.Printf("Warning: failed to cache oauth token: %v", err)
		return
	}
	defer f.Close()
	gob.NewEncoder(f).Encode(token)
}

func condDebugTransport(rt http.RoundTripper) http.RoundTripper {
	if *debug {
		return &logTransport{rt}
	}
	return rt
}

func getOAuthClient(config *oauth.Config) *http.Client {
	cacheFile := tokenCacheFile(config)
	token, err := tokenFromFile(cacheFile)
	if err != nil {
		token = tokenFromWeb(config)
		saveToken(cacheFile, token)
	} else {
		log.Printf("Using cached token %#v from %q", token, cacheFile)
	}

	t := &oauth.Transport{
		Token:     token,
		Config:    config,
		Transport: condDebugTransport(http.DefaultTransport),
	}
	return t.Client()
}

func tokenFromWeb(config *oauth.Config) *oauth.Token {
	ch := make(chan string)
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/favicon.ico" {
			http.Error(rw, "", 404)
			return
		}
		if req.FormValue("state") != randState {
			log.Printf("State doesn't match: req = %#v", req)
			http.Error(rw, "", 500)
			return
		}
		if code := req.FormValue("code"); code != "" {
			fmt.Fprintf(rw, "<h1>Success</h1>Authorized.")
			rw.(http.Flusher).Flush()
			ch <- code
			return
		}
		log.Printf("no code")
		http.Error(rw, "", 500)
	}))
	defer ts.Close()

	config.RedirectURL = ts.URL
	authUrl := config.AuthCodeURL(randState)
	go openUrl(authUrl)
	log.Printf("Authorize this app at: %s", authUrl)
	code := <-ch
	log.Printf("Got code: %s", code)

	t := &oauth.Transport{
		Config:    config,
		Transport: condDebugTransport(http.DefaultTransport),
	}
	_, err := t.Exchange(code)
	if err != nil {
		log.Fatalf("Token exchange error: %v", err)
	}
	return t.Token
}

func openUrl(url string) {
	try := []string{"xdg-open", "google-chrome", "open"}
	for _, bin := range try {
		err := exec.Command(bin, url).Run()
		if err == nil {
			return
		}
	}
	log.Printf("Error opening URL in browser.")
}

func valueOrFileContents(value string, filename string) string {
	if value != "" {
		return value
	}
	slurp, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error reading %q: %v", filename, err)
	}
	return strings.TrimSpace(string(slurp))
}
