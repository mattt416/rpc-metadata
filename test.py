import sys
import yaml

import click


stream = file('products.yml', 'r')
data = yaml.load(stream)


def get_components(product=None):
    c = []
    for p in data['products']:
        if (product and product == p['name']) or product is None:
            for component in p['components']:
                if component['name'] not in c:
                    c.append(component['name'])
    return c


def get_products(component=None):
    p = []
    for product in data['products']:
        if (component and component in get_components(product['name'])) or component is None:
            p.append(product['name'])
    return p


@click.group()
def cli():
    pass


@click.command()
@click.option('--component')
def products(component):
    p = get_products(component)
    print(p)


@click.command()
def components():
    c = get_components()
    print(c)


cli.add_command(products)
cli.add_command(components)

cli()
