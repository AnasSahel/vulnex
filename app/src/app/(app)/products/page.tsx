import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getUserProducts } from "@/lib/queries";
import { ProductList } from "@/components/dashboard/product-list";

export default async function DashboardPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) redirect("/login");

  const products = await getUserProducts(session.user.id);

  return (
    <div className="space-y-8 max-w-6xl">
      <div className="animate-fade-up">
        <h1 className="text-2xl font-bold tracking-tight">Products</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Manage and monitor your products
        </p>
      </div>

      <div className="animate-fade-up" style={{ animationDelay: "50ms" }}>
        <ProductList products={products} />
      </div>
    </div>
  );
}
