func allowCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func isValidDomain(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	for _, domain := range whitelisted_domains {
		if strings.HasSuffix(origin, domain) {
			return true
		}
	}
	return false
}

func thaddeusDecorator(h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if isValidDomain(req) {
			allowCors(&w)
			h(w, req)
		}
	}
}
