import yaml
import sys


def main():
    stream = file('products.yml', 'r')

    data = yaml.load(stream)

    if len(sys.argv) != 2:
        sys.exit(1)

    if sys.argv[1] == "products":
        print(products(data))
    elif sys.argv[1] == "components":
        print(components(data))
    else:
        print(component_in_products(data, sys.argv[1]))


def products(data):
    products = []
    for product in data:
        products.append(product)
    return products


def components(data):
    c = []
    for product in data:
        for component in data[product]:
            if component not in c:
                c.append(component)
    return c


def component_in_products(data, component):
    products = []
    for product in data:
        if component in data[product]:
            products.append(product)
    return products


if __name__ == "__main__":
    main()
