package ports

type PortScanner interface {
	Scan(target string) ([]int, error)
}
