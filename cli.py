import sys
import yaml

import click
import git


stream = file('products.yml', 'r')
data = yaml.load(stream)


def get_component_list(product=None):
    c = []
    for p in data['products']:
        if (product and product == p['name']) or product is None:
            for version in p['versions']:
                for component in version['components']:
                    if component['name'] not in c:
                        c.append(component['name'])
    return c


def get_product_list(component=None):
    p = []
    for product in data['products']:
        if (component and component in get_component_list(product['name'])) or component is None:
            p.append(product['name'])
    return p


@click.group()
def cli():
    pass


@click.command()
@click.option('--component')
def products(component):
    p = get_product_list(component)
    print(p)


@click.command()
def components():
    c = get_component_list()
    print(c)


@click.command()
@click.argument('product', nargs=1)
@click.argument('version', nargs=1)
def clone(product, version):
    for p in data['products']:
        if p['name'] == product:
            for v in p['versions']:
                if v['version'] == version:
                    for c in v['components']:
                        clone_dir = '/opt/%s' % c['name']
                        print('Cloning %s to %s ...' % (c['name'], clone_dir))
                        git.Repo.clone_from(c['repo'], clone_dir, branch=c['version'])


cli.add_command(products)
cli.add_command(components)
cli.add_command(clone)

cli()
