package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
)

type inventoryPageData struct {
	Title       string
	Subtitle    string
	RoutePrefix string
	Flash       string
}

type unitOption struct {
	ID string
}

type productOption struct {
	ID    string
	Name  string
	Line  string
	Units []unitOption
}

type cambioFormData struct {
	Title               string
	ProductoID          string
	Productos           []productOption
	Unidades            []unitOption
	PersonaCambio       string
	Notas               string
	Salientes           []string
	SalientesMap        map[string]bool
	IncomingMode        string
	IncomingExistingID  string
	IncomingExistingQty int
	IncomingNewSKU      string
	IncomingNewName     string
	IncomingNewLine     string
	IncomingNewQty      int
	Errors              map[string]string
}

type cambioConfirmData struct {
	Title               string
	ProductoID          string
	ProductoNombre      string
	PersonaCambio       string
	Notas               string
	Salientes           []string
	Entrantes           []string
	IncomingMode        string
	IncomingExistingID  string
	IncomingExistingQty int
	IncomingNewSKU      string
	IncomingNewName     string
	IncomingNewLine     string
	IncomingNewQty      int
}

func findProduct(products []productOption, id string) (productOption, bool) {
	for _, product := range products {
		if product.ID == id {
			return product, true
		}
	}
	return productOption{}, false
}

func buildEntranteIDs(prefix string, qty int) []string {
	ids := make([]string, 0, qty)
	for i := 1; i <= qty; i++ {
		ids = append(ids, prefix+"-"+strconv.Itoa(i))
	}
	return ids
}

func buildSalientesMap(salientes []string) map[string]bool {
	mapped := make(map[string]bool, len(salientes))
	for _, id := range salientes {
		mapped[id] = true
	}
	return mapped
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	tmpl := template.Must(template.ParseFiles(
		"templates/inventario.html",
		"templates/venta_new.html",
		"templates/venta_confirm.html",
		"templates/cambio_new.html",
		"templates/cambio_confirm.html",
	))

	paymentMethods := []string{"Efectivo", "Transferencia", "Tarjeta", "Nequi", "Daviplata", "Bre-B"}

	products := []productOption{
		{
			ID:    "P-001",
			Name:  "Proteína Balance 500g",
			Line:  "Nutrición",
			Units: []unitOption{{ID: "U-001"}, {ID: "U-002"}, {ID: "U-003"}},
		},
		{
			ID:    "P-002",
			Name:  "Crema Regeneradora",
			Line:  "Dermocosmética",
			Units: []unitOption{{ID: "U-101"}, {ID: "U-102"}, {ID: "U-103"}, {ID: "U-104"}},
		},
		{
			ID:    "P-003",
			Name:  "Leche Pediátrica Premium",
			Line:  "Pediatría",
			Units: []unitOption{{ID: "U-201"}},
		},
	}

	type ventaFormData struct {
		Title       string
		ProductoID  string
		Cantidad    int
		PrecioFinal string
		MetodoPago  string
		Notas       string
		Errors      map[string]string
		MetodoPagos []string
		RoutePrefix string
	}

	type ventaConfirmData struct {
		Title       string
		ProductoID  string
		Cantidad    int
		PrecioFinal string
		MetodoPago  string
		Notas       string
	}

	http.HandleFunc("/inventario", func(w http.ResponseWriter, r *http.Request) {
		flash := r.URL.Query().Get("mensaje")
		data := inventoryPageData{
			Title:       "Pantalla Inventario (por producto)",
			Subtitle:    "Control por producto con ventas, cambios y auditoría de unidades en FIFO.",
			RoutePrefix: "",
			Flash:       flash,
		}
		if err := tmpl.ExecuteTemplate(w, "inventario.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/venta/new", func(w http.ResponseWriter, r *http.Request) {
		productID := r.URL.Query().Get("producto_id")
		cantidad := 1
		if qty := r.URL.Query().Get("cantidad"); qty != "" {
			if parsed, err := strconv.Atoi(qty); err == nil && parsed > 0 {
				cantidad = parsed
			}
		}

		data := ventaFormData{
			Title:       "Registrar venta",
			ProductoID:  productID,
			Cantidad:    cantidad,
			MetodoPago:  paymentMethods[0],
			MetodoPagos: paymentMethods,
		}

		if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/cambio/new", func(w http.ResponseWriter, r *http.Request) {
		productID := r.URL.Query().Get("producto_id")
		if productID == "" {
			productID = products[0].ID
		}
		cantidad := 1
		if qty := r.URL.Query().Get("cantidad"); qty != "" {
			if parsed, err := strconv.Atoi(qty); err == nil && parsed > 0 {
				cantidad = parsed
			}
		}

		selectedProduct, ok := findProduct(products, productID)
		if !ok {
			selectedProduct = products[0]
			productID = selectedProduct.ID
		}

		salientes := make([]string, 0, cantidad)
		for i := 0; i < cantidad && i < len(selectedProduct.Units); i++ {
			salientes = append(salientes, selectedProduct.Units[i].ID)
		}

		data := cambioFormData{
			Title:               "Registrar cambio",
			ProductoID:          productID,
			Productos:           products,
			Unidades:            selectedProduct.Units,
			Salientes:           salientes,
			SalientesMap:        buildSalientesMap(salientes),
			IncomingMode:        "existing",
			IncomingExistingID:  products[0].ID,
			IncomingExistingQty: cantidad,
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/venta", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/venta/new", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
			return
		}

		productID := r.FormValue("producto_id")
		qtyValue := r.FormValue("cantidad")
		precioValue := r.FormValue("precio_final_venta")
		metodoPago := r.FormValue("metodo_pago")
		notas := r.FormValue("notas")

		errors := make(map[string]string)
		cantidad, err := strconv.Atoi(qtyValue)
		if err != nil || cantidad <= 0 {
			errors["cantidad"] = "La cantidad debe ser un número positivo."
		}
		if productID == "" {
			errors["producto_id"] = "Selecciona un producto válido."
		}
		if precioValue == "" {
			errors["precio_final_venta"] = "Ingresa el precio final de venta."
		} else if parsed, err := strconv.ParseFloat(precioValue, 64); err != nil || parsed <= 0 {
			errors["precio_final_venta"] = "El precio debe ser un número mayor a 0."
		}

		validMethod := false
		for _, method := range paymentMethods {
			if metodoPago == method {
				validMethod = true
				break
			}
		}
		if !validMethod {
			errors["metodo_pago"] = "Selecciona un método de pago válido."
		}

		if len(errors) > 0 {
			data := ventaFormData{
				Title:       "Registrar venta",
				ProductoID:  productID,
				Cantidad:    cantidad,
				PrecioFinal: precioValue,
				MetodoPago:  metodoPago,
				Notas:       notas,
				Errors:      errors,
				MetodoPagos: paymentMethods,
			}
			w.WriteHeader(http.StatusBadRequest)
			if err := tmpl.ExecuteTemplate(w, "venta_new.html", data); err != nil {
				http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
			}
			return
		}

		confirmData := ventaConfirmData{
			Title:       "Venta registrada",
			ProductoID:  productID,
			Cantidad:    cantidad,
			PrecioFinal: precioValue,
			MetodoPago:  metodoPago,
			Notas:       notas,
		}
		if err := tmpl.ExecuteTemplate(w, "venta_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/cambio", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/cambio/new", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "No se pudo leer el formulario", http.StatusBadRequest)
			return
		}

		productID := r.FormValue("producto_id")
		personaCambio := r.FormValue("persona_del_cambio")
		notas := r.FormValue("notas")
		salientes := r.Form["salientes"]
		incomingMode := r.FormValue("incoming_mode")
		incomingExistingID := r.FormValue("incoming_existing_id")
		incomingExistingQtyValue := r.FormValue("incoming_existing_qty")
		incomingNewSKU := r.FormValue("incoming_new_sku")
		incomingNewName := r.FormValue("incoming_new_name")
		incomingNewLine := r.FormValue("incoming_new_line")
		incomingNewQtyValue := r.FormValue("incoming_new_qty")

		errors := make(map[string]string)

		selectedProduct, ok := findProduct(products, productID)
		if !ok {
			errors["producto_id"] = "Selecciona un producto válido."
			selectedProduct = products[0]
			productID = selectedProduct.ID
		}

		if personaCambio == "" {
			errors["persona_del_cambio"] = "Ingresa la persona responsable del cambio."
		}

		unitLookup := make(map[string]struct{})
		for _, unit := range selectedProduct.Units {
			unitLookup[unit.ID] = struct{}{}
		}
		validSalientes := make([]string, 0, len(salientes))
		for _, unitID := range salientes {
			if _, ok := unitLookup[unitID]; ok {
				validSalientes = append(validSalientes, unitID)
			}
		}
		if len(validSalientes) == 0 {
			errors["salientes"] = "Selecciona al menos una unidad disponible como saliente."
		}
		salientes = validSalientes

		incomingExistingQty := 0
		if incomingExistingQtyValue != "" {
			if parsed, err := strconv.Atoi(incomingExistingQtyValue); err == nil {
				incomingExistingQty = parsed
			}
		}
		incomingNewQty := 0
		if incomingNewQtyValue != "" {
			if parsed, err := strconv.Atoi(incomingNewQtyValue); err == nil {
				incomingNewQty = parsed
			}
		}

		if incomingMode != "existing" && incomingMode != "new" {
			errors["incoming_mode"] = "Selecciona el tipo de entrada."
		}

		if incomingMode == "existing" {
			if incomingExistingID == "" {
				errors["incoming_existing_id"] = "Selecciona el producto entrante."
			}
			if incomingExistingQty <= 0 {
				errors["incoming_existing_qty"] = "Ingresa una cantidad válida para la entrada."
			}
		} else if incomingMode == "new" {
			if incomingNewSKU == "" {
				errors["incoming_new_sku"] = "Ingresa el SKU del producto nuevo."
			}
			if incomingNewName == "" {
				errors["incoming_new_name"] = "Ingresa el nombre del producto nuevo."
			}
			if incomingNewQty <= 0 {
				errors["incoming_new_qty"] = "Ingresa una cantidad válida para la entrada."
			}
		}

		if len(errors) > 0 {
			data := cambioFormData{
				Title:               "Registrar cambio",
				ProductoID:          productID,
				Productos:           products,
				Unidades:            selectedProduct.Units,
				PersonaCambio:       personaCambio,
				Notas:               notas,
				Salientes:           salientes,
				SalientesMap:        buildSalientesMap(salientes),
				IncomingMode:        incomingMode,
				IncomingExistingID:  incomingExistingID,
				IncomingExistingQty: incomingExistingQty,
				IncomingNewSKU:      incomingNewSKU,
				IncomingNewName:     incomingNewName,
				IncomingNewLine:     incomingNewLine,
				IncomingNewQty:      incomingNewQty,
				Errors:              errors,
			}
			w.WriteHeader(http.StatusBadRequest)
			if err := tmpl.ExecuteTemplate(w, "cambio_new.html", data); err != nil {
				http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
			}
			return
		}

		entrantes := []string{}
		if incomingMode == "existing" {
			entrantes = buildEntranteIDs("ENT-"+incomingExistingID, incomingExistingQty)
		} else {
			entrantes = buildEntranteIDs("ENT-"+incomingNewSKU, incomingNewQty)
		}

		confirmData := cambioConfirmData{
			Title:               "Cambio registrado",
			ProductoID:          productID,
			ProductoNombre:      selectedProduct.Name,
			PersonaCambio:       personaCambio,
			Notas:               notas,
			Salientes:           salientes,
			Entrantes:           entrantes,
			IncomingMode:        incomingMode,
			IncomingExistingID:  incomingExistingID,
			IncomingExistingQty: incomingExistingQty,
			IncomingNewSKU:      incomingNewSKU,
			IncomingNewName:     incomingNewName,
			IncomingNewLine:     incomingNewLine,
			IncomingNewQty:      incomingNewQty,
		}

		if err := tmpl.ExecuteTemplate(w, "cambio_confirm.html", confirmData); err != nil {
			http.Error(w, "Error al renderizar el template", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/inventario", http.StatusFound)
	})

	addr := ":" + port
	log.Printf("Servidor activo en http://localhost:%s/inventario", port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
