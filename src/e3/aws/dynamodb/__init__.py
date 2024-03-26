from __future__ import annotations
from typing import TYPE_CHECKING
import logging
import re
import time
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from typing import Any, Literal, Optional

    OperationType = Literal["or", "between", "contains"]
    """Operations supported by DynamoDB.scan."""

logger = logging.getLogger("e3.aws.dynamodb")

OR_OPERATION: OperationType = "or"
BETWEEN_OPERATION: OperationType = "between"
CONTAINS_OPERATION: OperationType = "contains"


class DynamoDB:
    """DynamoDB abstraction."""

    def __init__(
        self,
        client: Any,
    ) -> None:
        """Initialize DynamoDB table."""
        self.client = client

    def load_data(
        self,
        items: list[dict[str, Any]],
        table_name: str,
        keys: list[str],
        exist_ok: Optional[bool] = None,
    ) -> None:
        """Add multiple items to a table.

        :param items: items to add
        :param table_name: table where the items will be added
        :param keys: the primary keys of the item
        :param exist_ok: if False, an error is raised when an item already exists
        :raises RuntimeError: error raised when data fails to be loaded
        """
        logger.info(f"loading data to {table_name} table...")
        for item in items:
            self.add_item(item, table_name=table_name, keys=keys, exist_ok=exist_ok)

    def add_item(
        self,
        item: dict[str, Any],
        table_name: str,
        keys: list[str],
        exist_ok: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Add item to a table.

        :param item: item to add
        :param table_name: table where the item will be added
        :param keys: the primary keys of the item
        :param exist_ok: if False, an error is raised when the item already exists
        :raises RuntimeError: error raised when the item fails to be added
        :return: response to the request
        """
        table = self.client.Table(table_name)

        logger.info(f"Adding item: {item} to {table_name}")
        params: dict[str, Any] = {"Item": item}
        if not exist_ok:
            params.update(
                {
                    "ConditionExpression": " AND ".join(
                        [f"attribute_not_exists(#{key})" for key in keys]
                    ),
                    "ExpressionAttributeNames": {f"#{key}": key for key in keys},
                }
            )

        result = table.put_item(**params)
        if result["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise RuntimeError("Put Item Error")
        return result

    def get_item(
        self, item: dict[str, Any], table_name: str, keys: list[str]
    ) -> dict[str, Any]:
        """Retrieve an item from a table.

        :param item: item we want to retrieve
        :param table_name: table containing the item
        :param keys: the primary keys of the item
        :return: retrieved item
        """
        table = self.client.Table(table_name)
        logger.info(f"Retrieving item {item} from {table_name}...")
        try:
            response = table.get_item(
                Key={key: item[key] for key in keys if key in item.keys()}
            )
            logger.debug(f"Get_item response: {response}")
        except ClientError as e:
            logger.error(e)
            return {}
        else:
            return response.get("Item", {})

    def batch_get_items(
        self, items: list[dict[str, Any]], table_name: str, keys: list[str]
    ) -> list[dict[str, Any]]:
        """Retrieve multiple items from a table.

        When Amazon DynamoDB cannot process all items in a batch, a set of unprocessed
        keys is returned. This function uses an exponential backoff algorithm to retry
        getting the unprocessed keys until all are retrieved or the specified
        number of tries is reached.

        :param items: items we want to retrieve
        :param table_name: table containing the items
        :param keys: the primary keys of the items
        :return: retrieved item
        """
        logger.info(f"Retrieving items {items} from {table_name}...")
        res = []

        tries = 0
        max_tries = 5
        sleepy_time = 1  # Start with 1 second of sleep, then exponentially increase.
        batch_keys = {
            table_name: {
                "Keys": [
                    {key: item[key] for key in keys if key in item.keys()}
                    for item in items
                ],
                "ConsistentRead": True,
            }
        }

        while tries < max_tries:
            try:
                response = self.client.batch_get_item(
                    RequestItems=batch_keys,
                )
                res.extend(response.get("Responses", {table_name: []})[table_name])
                logger.debug(f"Get_item response: {response}")
                unprocessed = response["UnprocessedKeys"]
                if len(unprocessed) > 0:  # all: no cover"
                    # Testing this case is difficult as it requires a table
                    # with more than 16MB of data
                    batch_keys = unprocessed
                    unprocessed_count = sum(
                        [len(batch_key["Keys"]) for batch_key in batch_keys.values()]  # type: ignore
                    )
                    logger.info(
                        "%s unprocessed keys returned. Sleep, then retry.",
                        unprocessed_count,
                    )
                    tries += 1
                    if tries < max_tries:
                        logger.info("Sleeping for %s seconds.", sleepy_time)
                        time.sleep(sleepy_time)
                        sleepy_time = min(sleepy_time * 2, 32)
                else:
                    break
            except ClientError as e:
                logger.error(e)
                return []
        return res

    def update_item(
        self,
        item: dict[str, Any],
        table_name: str,
        keys: tuple[str, str],
        data: dict[str, Any],
        condition_expression: str | None = None,
        expression_attribute_names: dict[str, str] | None = None,
        expression_attribute_values: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Update an item of a table.

        :param item: item to be updated
        :param table_name: name of the table containing the item
        :param keys: the primary keys of the item to be updated
        :param data: a dict with the updated values of the item
        :param condition_expression: a condition that must be
            satisfied in order for a conditional update to succeed
        :param expression_attribute_names: one or more substitution
            tokens for attribute names in an expression
        :param expression_attribute_values: one or more values
            that can be substituted in an expression
        :raises RuntimeError: error raised when update fails
        :return: db response to the request
        """
        table = self.client.Table(table_name)
        logger.info(f"Updating {item} of table {table_name}")

        # get attributes names
        exp_attr_names = {f"#{s.upper()}": s for s in list(data.keys())}

        # get attributes values
        exp_attr_values = {f":{k}": v for k, v in data.items()}

        temp = zip(list(exp_attr_names.keys()), list(exp_attr_values.keys()))
        update_exp = " , ".join([f"{n} = {v}" for n, v in temp])
        update_exp = f"SET {update_exp}"

        # Add the user provided attribute names to default ones
        if expression_attribute_names is not None:
            exp_attr_names.update(expression_attribute_names)

        # Add the user provided attribute values to default ones
        if expression_attribute_values is not None:
            exp_attr_values.update(expression_attribute_values)

        logger.debug(f"ExpressionAttributeValues: {exp_attr_values}")
        logger.debug(f"ExpressionAttributeNames: {exp_attr_names}")
        logger.debug(f"UpdateExpression: {update_exp}")

        params = {
            "Key": {key: item[key] for key in keys if key in item.keys()},
            "ExpressionAttributeValues": exp_attr_values,
            "ExpressionAttributeNames": exp_attr_names,
            "UpdateExpression": update_exp,
            "ReturnValues": "UPDATED_NEW",
        }

        if condition_expression is not None:
            params["ConditionExpression"] = condition_expression

        result = table.update_item(**params)

        if result["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise RuntimeError("Update Item Error")
        return result

    def query_items(
        self,
        table_name: str,
        query: dict[str, list[str]],
        sort_key: tuple[str, str] | None = None,
        index_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query items from a table.

        :param table_name: name of the table
        :param query: a dict containing the key-values to query for
            e.g. {"name": ["John", "Robert"]}
        :param index_name: the name of an index to query, defaults to None
        :param sort_key: sort key-value of the table or the index to use as
            filter expression on the query
        :return: result of the query
        """
        table = self.client.Table(table_name)
        logger.info(f"Quering table {table_name} with {query}")
        attr_name = list(query.keys())[0]
        attr_value = list(query.values())[0][0]
        exp_name = f"#{attr_name.upper()}"

        sort_key_attr: tuple[dict[str, str], dict[str, str], str] = (
            {},  # attribute values
            {},  # attibute names
            "",  # expression
        )
        if sort_key:
            key = sort_key[0]
            sort_key_attr = (
                {f":{key}": sort_key[1]},
                {f"#{key}": f"{key}"},
                f"and #{key} = :{key}",
            )

        attr = {
            "ExpressionAttributeValues": {":val": attr_value, **sort_key_attr[0]},
            "ExpressionAttributeNames": {exp_name: attr_name, **sort_key_attr[1]},
            "KeyConditionExpression": f"{exp_name} = :val {sort_key_attr[2]}",
        }

        if index_name:
            attr["IndexName"] = index_name

        paging = True
        items = []
        while paging:
            result = table.query(**attr)
            items += result["Items"]
            if "LastEvaluatedKey" in result:
                # we have not scanned all table
                attr.update({"ExclusiveStartKey": result["LastEvaluatedKey"]})
            else:
                paging = False

        return items

    def scan(
        self,
        table_name: str,
        query: dict[str, list[Any]] | None = None,
        opt: OperationType = OR_OPERATION,
        index_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return all items that match the query's criteria.

        if query is None, it returns all elements

        :param table_name: Table name
        :param query: dictionary where the key represents a table
            field and value represent a list of possible values
            (e.g., {'release': ['23.1', '23.2'])}.
            For between operation the syntax is the following:
            {:field: [lower_bound, upper_bound] }
            For contains operations the syntax is ;
            {:field: [:value]}.
        :param opt: operation to use on different values given
        :param index_name: the name of an index to query.
        :return: selected items
        """
        table = self.client.Table(table_name)
        attr = {}
        if query:
            exp_attr_names = {f"#{s.upper()}": s for s in list(query.keys())}
            # values in dictionary is a list
            values = list(query.values())[0]

            # for the moment we support 'or', 'contains', and 'between'
            # operations
            if opt == BETWEEN_OPERATION:
                exp_attr_values = dict(zip([":lower", ":upper"], values))
                key = list(exp_attr_names.keys())[0]
                filter_exp = f"{key} between :lower and :upper"
            elif opt == CONTAINS_OPERATION:
                exp_attr_values = {":val": values[0]}
                key = list(exp_attr_names.keys())[0]
                filter_exp = f"contains ({key}, :val )"
            else:
                # remove non-alphanumerical caracters
                pattern = re.compile(r"[\W_]+")
                exp_attr_values = {
                    f":{pattern.sub('_', v)}": v for i, v in enumerate(values)
                }
                key = list(exp_attr_names.keys())[0]
                filter_exp = " or ".join(
                    [f"{key} = {values}" for values in exp_attr_values]
                )

            attr.update(
                {
                    "ExpressionAttributeValues": exp_attr_values,
                    "ExpressionAttributeNames": exp_attr_names,
                    "FilterExpression": filter_exp,
                }
            )

        if index_name:
            attr["IndexName"] = index_name

        logger.debug(f"scan attributes: {attr}")
        paging = True
        items = []
        while paging:
            result = table.scan(**attr)
            items += result["Items"]
            if "LastEvaluatedKey" in result:
                # we have not scanned all table
                attr.update({"ExclusiveStartKey": result["LastEvaluatedKey"]})
            else:
                paging = False

        return items

    def status(self, table_name: str) -> str:
        """Get table Status."""
        return self.client.Table(table_name).table_status
