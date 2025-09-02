def main_menu():
    while True:
        print("\nSOC Automation Toolkit")
        print("=====================")
        print("1) Ingestar logs")
        print("2) Detectar patrones sospechosos")
        print("3) Verificar IOCs")
        print("4) Generar reportes")
        print("5) Ejecutar respuesta automática")
        print("0) Salir")
        choice = input("Elija una opción: ")

        if choice == "1":
            print("Opción 1 seleccionada: Ingestar logs")
        elif choice == "2":
            print("Opción 2 seleccionada: Detectar patrones")
        elif choice == "3":
            print("Opción 3 seleccionada: Verificar IOCs")
        elif choice == "4":
            print("Opción 4 seleccionada: Generar reportes")
        elif choice == "5":
            print("Opción 5 seleccionada: Ejecutar respuesta")
        elif choice == "0":
            print("Saliendo...")
            break
        else:
            print("Opción no válida, intente de nuevo.")

if __name__ == "__main__":
    main_menu()
